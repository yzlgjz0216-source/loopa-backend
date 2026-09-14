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
  -- 用户表(简化版,先用于跑通聊天功能;
  -- 正式版需要和前端的 AuthManager 多登录体系打通,把 pi_uid / google_sub /
  -- solana_address / phone_number 这些身份标识都关联到这里的 user_id)
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
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
`);

module.exports = db;
