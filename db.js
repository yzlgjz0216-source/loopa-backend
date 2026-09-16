/* =========================================================================
   db.js — 数据库初始化与表结构定义
   开发阶段用 SQLite(单文件,零配置,方便你在自己电脑或云服务器上直接跑起来测试)。
   上生产、用户量上来后,建议迁移到 PostgreSQL —— 因为下面这些 SQL 语句写得
   比较通用(标准 SQL 语法),迁移时改动量不大,主要是换掉 better-sqlite3 这个驱动。
   ========================================================================= */

const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "loopa.db"));
db.pragma("journal_mode = WAL"); // 提升并发读写性能

db.exec(`
  -- 用户表:真正的账号体系,登录时会把 Pi/Google/Solana/BNB/手机号 这几种身份
  -- 都统一映射到这里的同一个 user_id,username 是对外展示的创作者/@handle
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    pi_uid TEXT UNIQUE,
    google_sub TEXT UNIQUE,
    solana_address TEXT UNIQUE,
    bnb_address TEXT UNIQUE,
    phone_number TEXT UNIQUE,
    age_tier TEXT,
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
    FOREIGN KEY (conversation_id) REFERENCES conversations(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);

  -- 打赏流水表:每一笔打赏的完整记录,从"已批准"到"已完成"的状态变化都留痕
  -- payment_id 上加唯一约束,防止 Pi SDK 的自动重试导致同一笔打赏被重复入账
  CREATE TABLE IF NOT EXISTS tips (
    id TEXT PRIMARY KEY,
    payment_id TEXT UNIQUE NOT NULL,
    tx_id TEXT,
    currency TEXT NOT NULL DEFAULT 'PI',
    amount REAL NOT NULL,
    sender_uid TEXT,
    creator_name TEXT NOT NULL,
    memo TEXT,
    status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'completed', 'failed')),
    created_at INTEGER NOT NULL,
    completed_at INTEGER
  );

  -- 创作者收益汇总表:只存已完成打赏的累计数字,查询主页时不用每次都汇总整张流水表
  CREATE TABLE IF NOT EXISTS creator_balances (
    creator_name TEXT PRIMARY KEY,
    total_pi REAL NOT NULL DEFAULT 0,
    tip_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_tips_creator ON tips(creator_name, status);

  -- 视频表:真实的内容发布记录
  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    creator_id TEXT NOT NULL,
    creator_name TEXT NOT NULL,   -- 冗余存一份用户名,渲染Feed时不用每次JOIN users表
    caption TEXT,
    video_url TEXT NOT NULL,
    thumbnail_url TEXT,
    view_count INTEGER NOT NULL DEFAULT 0,
    like_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('processing', 'published', 'removed')),
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
`);

// 兼容性迁移:如果是从旧版本升级上来的数据库,users表可能缺少这些新增字段,
// 逐个尝试添加,已存在的字段会报错但不影响其他字段继续添加(用 try/catch 逐条忽略)
const userMigrationColumns = [
  "username TEXT",
  "pi_uid TEXT",
  "google_sub TEXT",
  "solana_address TEXT",
  "bnb_address TEXT",
  "phone_number TEXT",
  "age_tier TEXT",
  "bio TEXT",
];
for (const col of userMigrationColumns) {
  try {
    db.exec(`ALTER TABLE users ADD COLUMN ${col}`);
  } catch (e) {
    // 字段已存在时会报错,属于正常情况,忽略即可
  }
}

module.exports = db;
