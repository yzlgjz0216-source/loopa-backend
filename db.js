/* =========================================================================
   db.js — 数据库初始化与表结构定义
   开发阶段用 SQLite(单文件,零配置,方便你在自己电脑或云服务器上直接跑起来测试)。
   上生产、用户量上来后,建议迁移到 PostgreSQL —— 因为下面这些 SQL 语句写得
   比较通用(标准 SQL 语法),迁移时改动量不大,主要是换掉 better-sqlite3 这个驱动。

   本轮(安全加固)改动总览,对应 GPT-6 审计报告 + 我自己复审发现的问题:
   1. 打开 PRAGMA foreign_keys —— 之前 CREATE TABLE 里写的所有 FOREIGN KEY
      声明其实从未真正生效(SQLite 默认关闭外键检查),现在真正打开。
   2. 给 pi_uid/google_sub/solana_address/bnb_address/phone_number/email
      这几个"身份标识"列,用 SQLite 支持的"部分唯一索引"
      (CREATE UNIQUE INDEX ... WHERE col IS NOT NULL)做真正的数据库级
      唯一约束 —— 之前只能在应用层"先查再写",并发请求下会有竞态窗口,
      两个请求可能同时通过检查、把同一个邮箱/钱包地址绑到两个不同账号上。
      这是 SQLite 里给可为空列做 UNIQUE 约束的标准写法(ALTER TABLE ADD
      COLUMN 本身不支持直接带 UNIQUE,但事后建一个部分唯一索引可以做到
      同样效果,而且不需要重建整张表)。
   3. 新增 refresh_tokens、auth_challenges、verification_codes、reports、
      blocks 这几张表,配合 server.js 这轮加的真实身份验证、Token 会话、
      钱包签名登录、邮箱/手机验证码、举报和拉黑功能。
   4. 打赏相关的 tips/creator_balances 结构性问题(用可变的显示名当主键、
      金额用浮点数存储)如果直接大改字段类型,对已经在跑的旧数据库不安全
      (SQLite 没法简单地给现有列加 NOT NULL 或改类型,需要整表重建),所以
      这里采用"新增字段 + 新增一张 v2 汇总表"的稳妥迁移方式,不删旧字段、
      不动旧数据,新逻辑一律读写新字段/新表,旧字段保留仅作历史兼容展示。
      详见下面 tips 表和新增的 creator_balances_v2 表的注释。
   ========================================================================= */

const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "loopa.db"));
db.pragma("journal_mode = WAL"); // 提升并发读写性能

// ⚠️ 关键修复(GPT-6审计 P1-10):SQLite 默认不启用外键约束检查,之前
// CREATE TABLE 里写的所有 FOREIGN KEY 只是"文档性"的,从未真正生效。
// PRAGMA 是按连接生效的,better-sqlite3 每次打开数据库都要重新设置一次。
db.pragma("foreign_keys = ON");

db.exec(`
  -- 用户表:真正的账号体系,登录时会把 Pi/Google/Solana/BNB/手机号/邮箱 这几种身份
  -- 都统一映射到这里的同一个 user_id,username 是对外展示的创作者/@handle。
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    pi_uid TEXT,
    google_sub TEXT,
    solana_address TEXT,
    bnb_address TEXT,
    phone_number TEXT,
    email TEXT,
    age_tier TEXT,
    bio TEXT,
    created_at INTEGER NOT NULL
  );

  -- 会话表:私信(direct)和群聊(group)共用一张表
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('direct', 'group')),
    group_name TEXT,           -- 仅群聊使用
    group_avatar_url TEXT,     -- 仅群聊使用
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
  );

  -- 会话成员关系表
  CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'admin', 'member')),
    joined_at INTEGER NOT NULL,
    last_read_at INTEGER DEFAULT 0,   -- 用于计算"未读消息数"
    PRIMARY KEY (conversation_id, user_id),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- 消息表
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'text' CHECK(message_type IN ('text', 'image', 'system')),
    created_at INTEGER NOT NULL,
    deleted_at INTEGER,   -- 本轮新增:软删除(撤回),不物理删除记录,方便日后申诉/审计
    FOREIGN KEY (conversation_id) REFERENCES conversations(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);

  -- 打赏流水表:每一笔打赏的完整记录,从"已批准"到"已完成"的状态变化都留痕
  -- payment_id 上加唯一约束,防止 Pi SDK 的自动重试导致同一笔打赏被重复入账。
  --
  -- ⚠️ 本轮新增 buyer_user_id / creator_user_id / amount_units 三个字段,
  -- 是 GPT-6 审计 P0-3、P1-8 两条问题的核心修复:
  --   - 旧的 amount(REAL 浮点数)不适合精确记账,新增 amount_units 存整数
  --     (amount * 10,000,000,对应 Pi/Stellar 体系常见的7位小数精度),
  --     避免浮点误差导致对账对不上。
  --   - 旧的 creator_name 是可变、不唯一的显示名,两个创作者可能同名、
  --     创作者改名后旧记录就"认不出"自己了。新增 creator_user_id 存不可变
  --     的账号ID,creator_name 只保留作为下单那一刻的展示快照,不再是记账依据。
  --   - 新增 buyer_user_id,记录这笔打赏真正是哪个 Ownlo 账号发起的
  --     (来自服务端验证过的登录会话,不是客户端自己说的),用于日后的
  --     交易记录查询、风控和纠纷处理。
  -- 旧字段 amount / creator_name 保留不删,只是不再是唯一依据,兼容还没
  -- 跑迁移脚本之前写入的历史数据展示。
  CREATE TABLE IF NOT EXISTS tips (
    id TEXT PRIMARY KEY,
    payment_id TEXT UNIQUE NOT NULL,
    tx_id TEXT,
    currency TEXT NOT NULL DEFAULT 'PI',
    amount REAL NOT NULL,
    amount_units INTEGER,
    buyer_user_id TEXT,
    creator_user_id TEXT,
    creator_name TEXT NOT NULL,
    memo TEXT,
    status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'completed', 'failed')),
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY (buyer_user_id) REFERENCES users(id),
    FOREIGN KEY (creator_user_id) REFERENCES users(id)
  );

  -- 创作者收益汇总表(旧版,按显示名主键——本轮之后不再写入,只读保留做历史兼容)
  CREATE TABLE IF NOT EXISTS creator_balances (
    creator_name TEXT PRIMARY KEY,
    total_pi REAL NOT NULL DEFAULT 0,
    tip_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  );

  -- 创作者收益汇总表 v2(本轮新增,真正的记账依据):按不可变的 creator_user_id
  -- 做主键,creator_name 只是最近一次已知的展示名快照,改名不会导致收益"丢失"。
  -- total_pi_units 是整数(见上面 tips.amount_units 的注释),不用浮点数。
  CREATE TABLE IF NOT EXISTS creator_balances_v2 (
    creator_user_id TEXT PRIMARY KEY,
    creator_name TEXT NOT NULL,
    total_pi_units INTEGER NOT NULL DEFAULT 0,
    tip_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (creator_user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_tips_creator ON tips(creator_name, status);
  -- ⚠️ 注意:idx_tips_creator_user / idx_tips_buyer 这两个索引依赖
  -- creator_user_id / buyer_user_id 这两个"本轮新增"的字段。对于全新数据库,
  -- 上面 CREATE TABLE 已经把这两个字段建好了,这里建索引没问题;但对于
  -- "已经在跑的旧生产数据库"(tips 表早就存在,没有这两个字段),
  -- CREATE TABLE IF NOT EXISTS 在这种情况下是空操作,不会补上缺的字段,
  -- 而这两个字段是靠下面第322行附近的 tipsMigrationColumns 迁移循环
  -- (ALTER TABLE tips ADD COLUMN ...)在稍后才补上的 —— 时间顺序上,
  -- 如果把这两条建索引语句留在这里(和 CREATE TABLE 同一个 db.exec 调用里),
  -- 会比字段迁移更早执行,导致 "SqliteError: no such column: creator_user_id"
  -- 这样的启动崩溃(2026-09 生产环境实际出现过的故障,现已移到迁移循环之后,
  -- 见下方 tipsMigrationColumns 循环结束后的 idx_tips_creator_user /
  -- idx_tips_buyer 建索引代码)。

  -- 视频表:真实的内容发布记录
  -- status 新增 'pending_review'(见 server.js 的 REQUIRE_VIDEO_REVIEW 开关):
  -- 开启人工审核模式后,新上传的视频先落这个状态,不出现在公开Feed里,
  -- 等后台审核通过后才会被标记为 published。
  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    creator_id TEXT NOT NULL,
    creator_name TEXT NOT NULL,   -- 冗余存一份用户名,渲染Feed时不用每次JOIN users表
    caption TEXT,
    video_url TEXT NOT NULL,
    thumbnail_url TEXT,
    view_count INTEGER NOT NULL DEFAULT 0,
    like_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('processing', 'pending_review', 'published', 'removed')),
    created_at INTEGER NOT NULL,
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_videos_feed ON videos(status, created_at);
  CREATE INDEX IF NOT EXISTS idx_videos_creator ON videos(creator_id, created_at);

  -- 点赞表:一个用户对同一个视频最多点一次赞,(video_id, user_id) 联合主键天然防止重复点赞
  CREATE TABLE IF NOT EXISTS likes (
    video_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (video_id, user_id),
    FOREIGN KEY (video_id) REFERENCES videos(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- 关注关系表:follower_id 关注了 creator_id
  CREATE TABLE IF NOT EXISTS follows (
    follower_id TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (follower_id, creator_id),
    FOREIGN KEY (follower_id) REFERENCES users(id),
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_follows_creator ON follows(creator_id);
  CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);

  -- 评论表
  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    video_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (video_id) REFERENCES videos(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id, created_at);

  /* =======================================================================
     以下均为本轮(安全加固)新增的表
     ======================================================================= */

  -- 刷新令牌表:配合 server.js 新的 JWT 登录会话机制。
  -- 登录/绑定验证通过后,后端签发一对 { accessToken(JWT,短期), refreshToken },
  -- accessToken 不落库(自包含签名,靠 JWT_SECRET 验证),refreshToken 是一串
  -- 随机字符串,这里只存它的哈希(不存明文),防止数据库被拖库后 refreshToken
  -- 被直接拿去使用;每次刷新都会把旧的标记为已撤销、签发一个新的(轮换机制),
  -- 防止一个泄露的 refreshToken 被长期重复使用。
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    replaced_by TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);

  -- 钱包登录挑战值(nonce)表:Solana/BNB 钱包登录或绑定时,后端先生成一条
  -- 一次性、有时效的随机消息,前端拿去给钱包签名,后端验证签名匹配这个地址后
  -- 才承认"这个人确实拥有这个钱包"——这是替换掉"客户端说是就是"的核心机制。
  -- 每条 nonce 用完(consumed_at 有值)或过期就不能再被拿来验证第二次。
  CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK(provider IN ('solana', 'bnb')),
    address TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_challenges_address ON auth_challenges(provider, address);

  -- 邮箱/手机验证码表:登录和绑定共用同一套。code_hash 存的是验证码的哈希,
  -- 不存明文(即使数据库被拖库,也不会直接暴露当时发出去的验证码);
  -- attempts 记录错误尝试次数,超过上限(见 server.js)直接判失败,防止有人
  -- 对着一个邮箱/手机号暴力枚举6位数字验证码。
  CREATE TABLE IF NOT EXISTS verification_codes (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL CHECK(channel IN ('email', 'phone')),
    identifier TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_codes_identifier ON verification_codes(channel, identifier);

  -- 举报表(本轮新增最基础版本):记录谁举报了什么内容/什么人、理由是什么。
  -- 目前只做"记下来",没有自动化处置或人工审核后台界面——这是有意为之的
  -- 起点而不是终点,上线前需要有真人定期查看 status='open' 的记录并处理。
  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('video', 'comment', 'user', 'message')),
    target_id TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'reviewed', 'dismissed')),
    FOREIGN KEY (reporter_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at);

  -- 拉黑表:blocker_id 拉黑了 blocked_id。拉黑之后:
  --   1) blocker 的 Feed 会过滤掉 blocked 发布的视频(见 /api/videos/feed);
  --   2) 双方都不能再创建新的私信会话或发消息(见 /api/conversations/direct)。
  -- 这是"起点版"的安全功能,还没有做"已存在的会话如何处理"这类更细的产品判断,
  -- 需要你后续根据实际产品需求补充(比如是否要连历史消息一起隐藏)。
  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (blocker_id, blocked_id),
    FOREIGN KEY (blocker_id) REFERENCES users(id),
    FOREIGN KEY (blocked_id) REFERENCES users(id)
  );
`);

// 兼容性迁移:如果是从旧版本升级上来的数据库,users表可能缺少这些新增字段,
// 逐个尝试添加,已存在的字段会报错但不影响其他字段继续添加。
// 注意:这里只处理"列已存在"这一种预期内的错误,其他真实迁移失败会被打印出来,
// 不再像上一版那样用空 catch 把所有错误都悄悄吞掉(GPT-6审计 P1-10 指出的问题)。
const userMigrationColumns = [
  "username TEXT",
  "pi_uid TEXT",
  "google_sub TEXT",
  "solana_address TEXT",
  "bnb_address TEXT",
  "phone_number TEXT",
  "email TEXT",
  "age_tier TEXT",
  "bio TEXT",
];
for (const col of userMigrationColumns) {
  try {
    db.exec(`ALTER TABLE users ADD COLUMN ${col}`);
  } catch (e) {
    if (!/duplicate column name/i.test(e.message)) {
      console.error(`[db migration] 添加字段 "${col}" 失败,且不是"字段已存在"这种预期内的情况,请人工检查:`, e.message);
    }
  }
}

// tips 表的新字段同理做兼容迁移(老数据库可能是本轮之前创建的,没有这几列)
const tipsMigrationColumns = ["amount_units INTEGER", "buyer_user_id TEXT", "creator_user_id TEXT"];
for (const col of tipsMigrationColumns) {
  try {
    db.exec(`ALTER TABLE tips ADD COLUMN ${col}`);
  } catch (e) {
    if (!/duplicate column name/i.test(e.message)) {
      console.error(`[db migration] tips 表添加字段 "${col}" 失败:`, e.message);
    }
  }
}

// ⚠️ 关键修复(2026-09 生产环境崩溃复盘):这两个索引依赖的
// creator_user_id / buyer_user_id 字段,必须等上面的迁移循环把字段真正
// 加到(可能是旧版本的)tips 表之后,才能建索引 —— 所以特意放在这里,
// 而不是放进最上面那个和 CREATE TABLE 挨在一起的大 db.exec() 里。
// 之前的版本把这两条语句写在了 CREATE TABLE 同一个 exec 调用里,对全新
// 数据库没问题,但对已经存在旧版 tips 表(缺这两个字段)的生产数据库,
// CREATE TABLE IF NOT EXISTS 是空操作、不会补字段,导致这两条建索引语句
// 在字段还不存在时就执行,抛出 "SqliteError: no such column: creator_user_id"
// 并让服务在启动阶段直接崩溃重启死循环。
try {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_tips_creator_user ON tips(creator_user_id, status)`);
} catch (e) {
  console.error(`[db migration] 建立索引 idx_tips_creator_user 失败:`, e.message);
}
try {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_tips_buyer ON tips(buyer_user_id)`);
} catch (e) {
  console.error(`[db migration] 建立索引 idx_tips_buyer 失败:`, e.message);
}

// messages 表的软删除字段
try {
  db.exec(`ALTER TABLE messages ADD COLUMN deleted_at INTEGER`);
} catch (e) {
  if (!/duplicate column name/i.test(e.message)) {
    console.error(`[db migration] messages 表添加 deleted_at 失败:`, e.message);
  }
}

/* ---------------------------------------------------------------------------
   本轮关键修复(GPT-6审计 P1-10 / P1-13):给身份标识列建立真正的数据库级
   唯一约束。SQLite 的 ALTER TABLE ADD COLUMN 不支持直接带 UNIQUE,但可以事后
   建一个"部分唯一索引"(只对非NULL的值生效)达到同样效果,不需要重建整张表。

   这能从根上堵住"两个并发请求同时通过应用层的重复性检查,把同一个邮箱/
   钱包地址绑到两个不同账号上"这种竞态条件——即使应用层代码检查有疏漏,
   数据库这一层也会直接拒绝写入并抛出约束错误,server.js 里已经对应捕获
   了这个错误并转换成友好的"已被绑定"提示。

   如果你的旧数据库里已经存在重复数据(比如迁移前就已经有两个账号绑了
   同一个手机号),下面这几条建索引的语句会失败并打印出来,需要你手动
   查出重复数据、决定保留哪一条、再重新运行一次让索引成功建立。
   --------------------------------------------------------------------------- */
const uniqueIdentityIndexes = [
  { name: "idx_users_pi_uid", col: "pi_uid" },
  { name: "idx_users_google_sub", col: "google_sub" },
  { name: "idx_users_solana_address", col: "solana_address" },
  { name: "idx_users_bnb_address", col: "bnb_address" },
  { name: "idx_users_phone_number", col: "phone_number" },
  { name: "idx_users_email", col: "email" },
];
for (const { name, col } of uniqueIdentityIndexes) {
  try {
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ${name} ON users(${col}) WHERE ${col} IS NOT NULL`);
  } catch (e) {
    console.error(
      `[db migration] 建立唯一索引 ${name}(字段 ${col})失败,很可能是数据库里已经存在重复值,` +
      `请手动查一下 "SELECT ${col}, COUNT(*) FROM users WHERE ${col} IS NOT NULL GROUP BY ${col} HAVING COUNT(*) > 1" ` +
      `找到重复记录、决定如何合并/清理后再重启服务:`,
      e.message
    );
  }
}

module.exports = db;
