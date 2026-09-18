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

  -- 收藏表(本轮新增):之前"收藏"只存在用户自己浏览器的本地缓存里,换设备/清缓存
  -- 就没了,后端压根没这张表。现在改成和点赞/关注一样,是服务端真正持久化的关系,
  -- 才能在"个人资料 → 收藏"这个新标签页里展示,换设备登录也能看到。
  CREATE TABLE IF NOT EXISTS collections (
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );
  CREATE INDEX IF NOT EXISTS idx_collections_user ON collections(user_id, created_at);

  -- 观看历史表(本轮新增):记录一个账号看过哪些视频、最近一次看的时间。
  -- 用 (user_id, video_id) 联合主键,同一条视频反复看只更新 watched_at,
  -- "历史浏览"这个新标签页里不会因为反复看同一条视频而堆出好多条重复记录。
  CREATE TABLE IF NOT EXISTS watch_history (
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    watched_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );
  CREATE INDEX IF NOT EXISTS idx_watch_history_user ON watch_history(user_id, watched_at);

  -- 通知表(本轮新增):平台/其他用户与这个账号之间的"提示信息"统一存这里——
  -- 有人赞了/评论了/关注了你(actor_id 是触发这条通知的人),或者是平台方发的
  -- 系统公告(type='system',actor_id 为空)。有了这张表,个人资料/首页才能有一个
  -- "通知"入口,把这些原来完全没有留痕、看不到历史的提示统一展示出来。
  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,         -- 通知给谁看
    type TEXT NOT NULL CHECK(type IN ('like', 'comment', 'follow', 'tip', 'system')),
    actor_id TEXT,                 -- 触发这条通知的人(系统公告没有,为空)
    video_id TEXT,                 -- 关联的视频(点赞/评论通知才有,可为空)
    content TEXT,                  -- 系统公告的正文,或者评论通知里附带的评论内容摘要
    created_at INTEGER NOT NULL,
    read_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (actor_id) REFERENCES users(id),
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);

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

  -- 直播间表(本轮新增,直播功能 Phase 0/1):一场直播从开播到结束是一行记录。
  -- room_name 是传给 LiveKit(以及以后如果切换到别家RTC服务商)的房间标识,
  -- 和 id 分开存是为了以后即使房间命名规则要改,也不影响 livestreams.id 这个
  -- 对外稳定的主键。provider 先固定写 'livekit',预留字段是为了以后如果真的
  -- 切换/对比服务商,不用改表结构。peak_viewer_count 只是一个粗略统计,不是
  -- 精确的实时在线人数来源(实时人数由 Socket.io 房间连接数现场计算)。
  CREATE TABLE IF NOT EXISTS livestreams (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    room_name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'livekit',
    title TEXT,
    status TEXT NOT NULL DEFAULT 'live' CHECK(status IN ('live', 'ended')),
    peak_viewer_count INTEGER NOT NULL DEFAULT 0,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    FOREIGN KEY (host_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_livestreams_status ON livestreams(status, started_at);
  CREATE INDEX IF NOT EXISTS idx_livestreams_host ON livestreams(host_id, started_at);

  /* =======================================================================
     以下为本轮(礼物/金币钱包/背景音乐)新增的表。
     架构(已和你确认过):用户先用真实 Pi 买"平台金币"(1 Pi = 10 金币,
     走和 tips 表一样的 Pi 支付 approve/complete 两段式流程),送礼物时
     直接从金币余额里瞬间扣除(不再单独发起一笔链上交易),主播收到礼物后
     累积到自己的"钻石余额"(diamond_balance)——钻石提现成 Pi 这件事本轮
     明确不做,先留着字段,后面再做提现功能。
     ======================================================================= */

  -- 钱包表:每个用户一行,一边是"花钱用的"金币余额,一边是"赚钱用的"钻石余额。
  -- 这两个余额完全独立、不能互相换算——金币只能花(买礼物),钻石只能攒(等未来提现)。
  CREATE TABLE IF NOT EXISTS wallets (
    user_id TEXT PRIMARY KEY,
    coin_balance INTEGER NOT NULL DEFAULT 0,
    diamond_balance INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- 金币购买流水表:结构完全照抄 tips 表的"两段式"记账模式(approved → completed),
  -- payment_id 唯一约束防止 Pi SDK 重试导致重复入账,道理和 tips 表注释里写的一样。
  -- coin_amount 是这笔订单最终要入账到 wallets.coin_balance 的金币数量
  -- (按下单那一刻的汇率算好,汇率以后即使调整也不影响历史订单的金币数)。
  CREATE TABLE IF NOT EXISTS coin_purchases (
    id TEXT PRIMARY KEY,
    payment_id TEXT UNIQUE NOT NULL,
    tx_id TEXT,
    buyer_user_id TEXT NOT NULL,
    pi_amount REAL NOT NULL,
    pi_amount_units INTEGER,
    coin_amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'completed', 'failed')),
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY (buyer_user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_coin_purchases_buyer ON coin_purchases(buyer_user_id, status);

  -- 礼物目录表:平台预设的礼物款式,coin_price 是这个礼物要花多少金币,
  -- tier 只是用来在前端分组展示(小礼物/中礼物/大礼物),不影响实际扣费逻辑。
  -- icon 存 emoji 字符串——遵循项目一贯的"视觉素材保持原创"原则,不使用
  -- 任何第三方图标/图片资源。
  CREATE TABLE IF NOT EXISTS gift_catalog (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT NOT NULL,
    coin_price INTEGER NOT NULL,
    tier TEXT NOT NULL DEFAULT 'small' CHECK(tier IN ('small', 'medium', 'large')),
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1
  );

  -- 送礼记录表:一次送礼(可以一次送多个,quantity)是一行。coin_cost 是这一行
  -- 实际扣掉的金币总数(= 送礼那一刻的单价 × quantity,即使目录后续改价也不影响历史记录)。
  -- livestream_id 允许为空,是为了以后如果要支持"给主播个人主页送礼"(不在直播间里)留出空间。
  CREATE TABLE IF NOT EXISTS gift_sends (
    id TEXT PRIMARY KEY,
    livestream_id TEXT,
    gift_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    coin_cost INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (livestream_id) REFERENCES livestreams(id),
    FOREIGN KEY (gift_id) REFERENCES gift_catalog(id),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_gift_sends_livestream ON gift_sends(livestream_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_gift_sends_receiver ON gift_sends(receiver_id, created_at);

  -- 背景音乐曲库表:随包附带的 8 首(is_builtin=1)是纯合成、自建的原创免版权音乐
  -- (见部署说明);is_builtin=0 的是你自己放进 public/music/ 目录、由下面
  -- syncMusicLibraryFromDisk() 自动扫描登记的曲目——这张表本身就是"共享曲库"的
  -- 唯一数据来源,以后直播背景音乐、发布视频配乐等任何功能都读同一张表,不用
  -- 各自维护一份。url 是相对路径,由后端 /music 静态目录直接提供,不依赖对象存储配置也能用。
  CREATE TABLE IF NOT EXISTS music_tracks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    artist TEXT,
    url TEXT NOT NULL,
    duration_seconds INTEGER,
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_builtin INTEGER NOT NULL DEFAULT 0
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
  "background_url TEXT", // 本轮新增:个人资料背景图,和已有的 avatar_url 同样是可为空的展示字段
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

// 本轮新增:"清空聊天记录"功能用的字段——只想清空自己这一侧看到的历史消息,
// 不影响对方,所以不能物理删除 messages 表里的记录,而是给每个会话成员单独记一个
// "清空到什么时间点"的时间戳,查消息列表时只要求 created_at > cleared_before 即可。
try {
  db.exec(`ALTER TABLE conversation_members ADD COLUMN cleared_before INTEGER DEFAULT 0`);
} catch (e) {
  if (!/duplicate column name/i.test(e.message)) {
    console.error(`[db migration] conversation_members 表添加 cleared_before 失败:`, e.message);
  }
}

// music_tracks 表的 is_builtin 字段同理做兼容迁移(老数据库可能是本轮之前创建的,没有这一列)
try {
  db.exec(`ALTER TABLE music_tracks ADD COLUMN is_builtin INTEGER NOT NULL DEFAULT 0`);
} catch (e) {
  if (!/duplicate column name/i.test(e.message)) {
    console.error(`[db migration] music_tracks 表添加 is_builtin 失败:`, e.message);
  }
}

// 本轮新增:礼物目录种子数据——只在表是空的时候插入一次,不会每次启动重复插入
// 或者覆盖掉你以后在后台手工调整过的价格/上下架状态。价格设计参考了抖音直播间
// "礼物墙"常见的价格分布(小礼物几金币到几十金币、大礼物几百到上千金币),
// 图标全部用 emoji,不使用任何第三方美术资源。
const giftCatalogSeed = [
  { id: "gift_rose", name: "玫瑰", icon: "🌹", price: 1, tier: "small", sort: 1 },
  { id: "gift_lollipop", name: "棒棒糖", icon: "🍭", price: 5, tier: "small", sort: 2 },
  { id: "gift_heart", name: "爱心", icon: "💗", price: 10, tier: "small", sort: 3 },
  { id: "gift_icecream", name: "冰淇淋", icon: "🍦", price: 20, tier: "small", sort: 4 },
  { id: "gift_beer", name: "干杯", icon: "🍻", price: 30, tier: "small", sort: 5 },
  { id: "gift_bell", name: "铃铛", icon: "🔔", price: 50, tier: "medium", sort: 6 },
  { id: "gift_gift", name: "礼物盒", icon: "🎁", price: 88, tier: "medium", sort: 7 },
  { id: "gift_ring", name: "戒指", icon: "💍", price: 199, tier: "medium", sort: 8 },
  { id: "gift_rocket", name: "火箭", icon: "🚀", price: 520, tier: "large", sort: 9 },
  { id: "gift_crown", name: "皇冠", icon: "👑", price: 1000, tier: "large", sort: 10 },
  { id: "gift_castle", name: "城堡", icon: "🏰", price: 1999, tier: "large", sort: 11 },
  { id: "gift_galaxy", name: "宇宙", icon: "🌌", price: 5200, tier: "large", sort: 12 },
];
try {
  const giftCount = db.prepare(`SELECT COUNT(*) AS c FROM gift_catalog`).get().c;
  if (giftCount === 0) {
    const insertGift = db.prepare(
      `INSERT INTO gift_catalog (id, name, icon, coin_price, tier, sort_order, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)`
    );
    const insertMany = db.transaction((rows) => {
      for (const g of rows) insertGift.run(g.id, g.name, g.icon, g.price, g.tier, g.sort);
    });
    insertMany(giftCatalogSeed);
    console.log(`[db seed] 已写入 ${giftCatalogSeed.length} 条礼物目录种子数据`);
  }
} catch (e) {
  console.error("[db seed] 写入礼物目录种子数据失败:", e.message);
}

// 本轮新增:背景音乐曲库种子数据——同样只在表为空时插入一次。这几首都是
// 本轮用代码纯合成生成的原创循环音乐(正弦/三角波振荡器 + 简单鼓点包络,
// 没有采样任何现成录音或已有作品),文件随后端一起部署在 public/music/ 目录下,
// 由 server.js 里的 /music 静态路由直接提供访问,不依赖 R2/对象存储配置。
const musicTracksSeed = [
  { id: "music_chillwave", title: "City Chillwave", artist: "Ownlo Originals", file: "music_chillwave.mp3", duration: 22, sort: 1 },
  { id: "music_dreamypad", title: "Dreamy Skyline", artist: "Ownlo Originals", file: "music_dreamypad.mp3", duration: 27, sort: 2 },
  { id: "music_upbeatpop", title: "Sunny Pop Loop", artist: "Ownlo Originals", file: "music_upbeatpop.mp3", duration: 16, sort: 3 },
  { id: "music_warmacoustic", title: "Warm Afternoon", artist: "Ownlo Originals", file: "music_warmacoustic.mp3", duration: 21, sort: 4 },
  { id: "music_midnightlo", title: "Midnight Lo-fi", artist: "Ownlo Originals", file: "music_midnightlo.mp3", duration: 25, sort: 5 },
  { id: "music_sparklebeat", title: "Sparkle Beat", artist: "Ownlo Originals", file: "music_sparklebeat.mp3", duration: 15, sort: 6 },
  { id: "music_softpiano", title: "Soft Piano Drift", artist: "Ownlo Originals", file: "music_softpiano.mp3", duration: 28, sort: 7 },
  { id: "music_partyenergy", title: "Party Energy", artist: "Ownlo Originals", file: "music_partyenergy.mp3", duration: 16, sort: 8 },
];
try {
  const musicCount = db.prepare(`SELECT COUNT(*) AS c FROM music_tracks`).get().c;
  if (musicCount === 0) {
    const insertTrack = db.prepare(
      `INSERT INTO music_tracks (id, title, artist, url, duration_seconds, sort_order, is_active, is_builtin) VALUES (?, ?, ?, ?, ?, ?, 1, 1)`
    );
    const insertMany = db.transaction((rows) => {
      for (const m of rows) insertTrack.run(m.id, m.title, m.artist, `/music/${m.file}`, m.duration, m.sort);
    });
    insertMany(musicTracksSeed);
    console.log(`[db seed] 已写入 ${musicTracksSeed.length} 条背景音乐种子数据`);
  }
} catch (e) {
  console.error("[db seed] 写入背景音乐种子数据失败:", e.message);
}

/* ---------------------------------------------------------------------------
   本轮新增:背景音乐"共享曲库"自动扫描登记 —— 对应你提的"以后加音乐只要
   复制文件进去就行"这个诉求。设计上没有做成一个独立的仓库/服务,而是继续放在
   这一个后端项目里的 public/music/ 目录下,原因很简单:额外拆一个仓库对"直播
   背景音乐"和"以后发布视频配乐"这两个用同一批文件、同一张数据库表的功能来说,
   只会多一层部署/同步的麻烦(还要单独 clone、单独更新),没有实际好处。
   "共享"体现在数据层:music_tracks 这一张表 + public/music/ 这一个目录,就是
   唯一的曲库来源,不管以后哪个功能要放背景音乐,都读写这一份,不需要各自复制。

   工作方式:每次服务启动时,扫描 public/music/ 目录下所有音频文件,把还没在
   数据库里登记过的文件自动插入一行(标题从文件名解析,支持"歌手 - 歌名.mp3"
   这种最常见的下载命名习惯,没有这个格式就直接用文件名当标题);同时反过来,
   如果数据库里登记过的某个"用户自己放的"文件已经从磁盘上被删掉了,就把它标成
   下架(is_active=0),避免播放器还想播一个已经不存在的文件。
   ⚠️ 没有引入任何第三方"读取MP3标签"的库(比如 music-metadata)——不是做不到,
   而是不想为了一个"标题好看一点"的锦上添花功能,再给你增加一次"装新依赖包
   踩坑"的风险(上次 livekit-server-sdk 装包踩过 npm 镜像同步延迟的坑,教训还在)。
   文件名解析已经能覆盖绝大多数你从各处下载下来的音乐文件的命名习惯了。
   --------------------------------------------------------------------------- */
const fs = require("fs");
const crypto = require("crypto");
const MUSIC_DIR = path.join(__dirname, "public", "music");
const SUPPORTED_MUSIC_EXT = [".mp3", ".m4a", ".wav", ".ogg", ".flac", ".aac"];

function parseTitleArtistFromFilename(filename) {
  const base = filename.replace(/\.[^.]+$/, ""); // 去掉扩展名
  // "歌手 - 歌名" / "歌手-歌名" 是下载音乐最常见的命名习惯,尽量识别出来拆成两段;
  // 识别不出这个格式就整个文件名当标题、歌手留空(后台以后也可以手工改)。
  const m = base.match(/^\s*(.+?)\s*[-–—]\s*(.+?)\s*$/);
  if (m && m[1] && m[2]) return { title: m[2], artist: m[1] };
  return { title: base, artist: null };
}

function syncMusicLibraryFromDisk() {
  let files;
  try {
    if (!fs.existsSync(MUSIC_DIR)) fs.mkdirSync(MUSIC_DIR, { recursive: true });
    files = fs.readdirSync(MUSIC_DIR).filter((f) => SUPPORTED_MUSIC_EXT.includes(path.extname(f).toLowerCase()));
  } catch (e) {
    console.error("[db] 扫描 public/music/ 目录失败:", e.message);
    return { added: 0, deactivated: 0 };
  }

  const existingByUrl = new Map(
    db.prepare(`SELECT id, url, is_builtin FROM music_tracks`).all().map((r) => [r.url, r])
  );

  let added = 0;
  const insertTrack = db.prepare(
    `INSERT INTO music_tracks (id, title, artist, url, duration_seconds, sort_order, is_active, is_builtin) VALUES (?, ?, ?, ?, NULL, ?, 1, 0)`
  );
  const seenUrls = new Set();
  files.forEach((filename, idx) => {
    const url = `/music/${encodeURIComponent(filename)}`;
    seenUrls.add(url);
    if (existingByUrl.has(url)) return; // 已经登记过,跳过——不覆盖你可能在数据库里手工改过的标题
    const { title, artist } = parseTitleArtistFromFilename(filename);
    const id = "music_user_" + crypto.createHash("sha1").update(filename).digest("hex").slice(0, 16);
    try {
      // sort_order 给一个很小的负数,配合下面 server.js 查询里的
      // "ORDER BY is_builtin ASC, sort_order ASC",让你自己放的曲目默认排在
      // 那 8 首内置合成曲前面(毕竟内置的那几首本来就只是占位示范用)。
      insertTrack.run(id, title, artist, url, idx - files.length);
      added++;
    } catch (e) {
      console.error(`[db] 登记曲库文件 "${filename}" 失败:`, e.message);
    }
  });

  // 反向检查:数据库里"非内置"的曲目,如果对应文件已经不在磁盘上了,标记下架
  let deactivated = 0;
  const deactivateStmt = db.prepare(`UPDATE music_tracks SET is_active = 0 WHERE id = ?`);
  for (const [url, row] of existingByUrl) {
    if (!row.is_builtin && !seenUrls.has(url)) {
      deactivateStmt.run(row.id);
      deactivated++;
    }
  }

  if (added || deactivated) {
    console.log(`[db] 背景音乐曲库自动扫描:新增 ${added} 首,下架 ${deactivated} 首(文件已不存在)`);
  }
  return { added, deactivated };
}

try {
  syncMusicLibraryFromDisk();
} catch (e) {
  console.error("[db] 启动时自动扫描背景音乐曲库失败:", e.message);
}

module.exports = db;
module.exports.syncMusicLibraryFromDisk = syncMusicLibraryFromDisk;
