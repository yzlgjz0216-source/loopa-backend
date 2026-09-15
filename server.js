/* =========================================================================
   server.js — Loopa 私信/群聊后端服务(MVP)

   本地运行方式:
     1) cd loopa-backend
     2) npm install
     3) npm start
   默认监听 http://localhost:4000

   ⚠️ 身份验证说明:
   当前用最简单的方式验证身份 —— 请求头里带 x-user-id,直接信任这个值。
   这只适用于本地开发联调阶段!正式上线前必须替换成真实的身份验证:
   前端应该发送登录时拿到的 accessToken(Pi)/credential(Google)/签名(Solana),
   后端验证通过后才能确定 x-user-id 对应的身份是真实的,否则任何人都能
   伪造别人的 user-id 冒充身份发消息、读别人的聊天记录 —— 这是重点安全隐患,
   多AI交叉审查时请把 requireAuth() 这个函数标为最高优先级检查对象。
   ========================================================================= */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

// 临时诊断用:记录所有到达服务器的请求,排查完连通性问题后可以删掉这几行
app.use((req, res, next) => {
  console.log(`[请求日志] ${req.method} ${req.path}`);
  next();
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } }); // 生产环境请把 origin 改成你的真实前端域名


/* -------------------------------------------------------------------------
   身份验证中间件(占位版,见文件头警告)
   ------------------------------------------------------------------------- */
function requireAuth(req, res, next) {
  const userId = req.headers["x-user-id"];
  if (!userId) return res.status(401).json({ error: "缺少 x-user-id,未登录" });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!user) return res.status(401).json({ error: "用户不存在" });

  req.userId = userId;
  next();
}


/* -------------------------------------------------------------------------
   用户接口(测试用,正式版由 AuthManager 的登录流程创建用户)
   ------------------------------------------------------------------------- */
app.post("/api/users", (req, res) => {
  const { displayName, avatarUrl } = req.body;
  if (!displayName) return res.status(400).json({ error: "displayName 必填" });

  const id = uuidv4();
  db.prepare(
    "INSERT INTO users (id, display_name, avatar_url, created_at) VALUES (?, ?, ?, ?)"
  ).run(id, displayName, avatarUrl || null, Date.now());

  res.json({ id, displayName, avatarUrl });
});


/* -------------------------------------------------------------------------
   Pi 支付接口:真正对接 Pi 官方服务端 API,完成 U2A 支付的"批准"和"完成"两步。

   ⚠️ 这两个接口是 Pi 支付流程里"必须由服务端完成"的关键环节,不能省略:
   用户在 Pi 钱包里点"同意"之后,支付并不会自动生效,必须由 App 的服务端
   调用 Pi 官方 API 明确"批准"这笔支付,链上交易广播后还要再调用一次
   "完成"接口确认交易哈希,整笔支付才算真正生效。

   需要在 .env 里配置 PI_API_KEY(Pi Developer Portal 里该 App 的 Server API Key,
   在"连接钱包"那一步完成后,App 详情页里可以找到)。
   参考: https://github.com/pi-apps/pi-platform-docs/blob/master/SDK_reference.md#payments
   ------------------------------------------------------------------------- */
const PI_API_BASE = "https://api.minepi.com/v2";

app.post("/api/payments/approve", async (req, res) => {
  console.log("[Payment] 收到批准请求,paymentId=", req.body?.paymentId, " 完整body=", JSON.stringify(req.body));
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: "paymentId 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Payment] ⚠️ PI_API_KEY 未配置或未被读取到,无法调用 Pi 官方 API,批准请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/approve`, {
      method: "POST",
      headers: { "Authorization": `Key ${process.env.PI_API_KEY}` },
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 批准支付失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 批准失败", detail: errText });
    }
    const payment = await response.json();

    // TODO(数据库联调点): 在这里把这笔待批准的支付记录写入自己的数据库(状态=已批准),
    // 方便后续对账、以及在 complete 阶段核实这笔支付确实是本平台发起的。

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 批准支付出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

app.post("/api/payments/complete", async (req, res) => {
  console.log("[Payment] 收到完成请求,paymentId=", req.body?.paymentId, " txid=", req.body?.txid);
  const { paymentId, txid } = req.body;
  if (!paymentId || !txid) return res.status(400).json({ error: "paymentId 和 txid 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Payment] ⚠️ PI_API_KEY 未配置或未被读取到,无法调用 Pi 官方 API,完成请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/complete`, {
      method: "POST",
      headers: {
        "Authorization": `Key ${process.env.PI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ txid }),
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 完成支付确认失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 完成确认失败", detail: errText });
    }
    const payment = await response.json();

    // TODO(数据库联调点): 更新数据库里这笔支付的状态为"已完成",
    // 并给对应的创作者账户增加积分余额(参考 PRD 里的打赏积分中间层设计)。

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 完成支付确认出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});


/* -------------------------------------------------------------------------
   会话接口
   ------------------------------------------------------------------------- */

// 获取当前用户的所有会话列表(按最后消息时间倒序,附带未读数)
app.get("/api/conversations", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      c.id, c.type, c.group_name, c.group_avatar_url,
      (SELECT content FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_message_at,
      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.created_at > cm.last_read_at) AS unread_count
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id
    WHERE cm.user_id = ?
    ORDER BY last_message_at DESC
  `).all(req.userId);

  res.json(rows);
});

// 创建或复用一个私信会话(两人之间只会有一个 direct 会话,重复创建会返回已存在的那个)
app.post("/api/conversations/direct", requireAuth, (req, res) => {
  const { targetUserId } = req.body;
  if (!targetUserId) return res.status(400).json({ error: "targetUserId 必填" });

  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = ?
    JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = ?
    WHERE c.type = 'direct'
  `).get(req.userId, targetUserId);

  if (existing) return res.json({ id: existing.id, existed: true });

  const conversationId = uuidv4();
  const now = Date.now();
  const insertConv = db.prepare(
    "INSERT INTO conversations (id, type, created_by, created_at) VALUES (?, 'direct', ?, ?)"
  );
  const insertMember = db.prepare(
    "INSERT INTO conversation_members (conversation_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)"
  );

  const tx = db.transaction(() => {
    insertConv.run(conversationId, req.userId, now);
    insertMember.run(conversationId, req.userId, now);
    insertMember.run(conversationId, targetUserId, now);
  });
  tx();

  res.json({ id: conversationId, existed: false });
});

// 创建群聊
app.post("/api/conversations/group", requireAuth, (req, res) => {
  const { groupName, memberIds } = req.body;
  if (!groupName || !Array.isArray(memberIds) || memberIds.length === 0) {
    return res.status(400).json({ error: "groupName 和 memberIds(数组) 必填" });
  }

  const conversationId = uuidv4();
  const now = Date.now();
  const insertConv = db.prepare(
    "INSERT INTO conversations (id, type, group_name, created_by, created_at) VALUES (?, 'group', ?, ?, ?)"
  );
  const insertMember = db.prepare(
    "INSERT INTO conversation_members (conversation_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)"
  );

  const tx = db.transaction(() => {
    insertConv.run(conversationId, groupName, req.userId, now);
    insertMember.run(conversationId, req.userId, "owner", now); // 建群者自动成为群主
    memberIds.forEach((uid) => {
      if (uid !== req.userId) insertMember.run(conversationId, uid, "member", now);
    });
  });
  tx();

  res.json({ id: conversationId });
});

// 拉取某个会话的历史消息(分页)
app.get("/api/conversations/:id/messages", requireAuth, (req, res) => {
  const { id } = req.params;
  const before = Number(req.query.before) || Date.now();
  const limit = Math.min(Number(req.query.limit) || 30, 100);

  const isMember = db.prepare(
    "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?"
  ).get(id, req.userId);
  if (!isMember) return res.status(403).json({ error: "你不是该会话成员" });

  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE conversation_id = ? AND created_at < ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(id, before, limit);

  res.json(messages.reverse());
});

// 标记已读
app.post("/api/conversations/:id/read", requireAuth, (req, res) => {
  db.prepare(
    "UPDATE conversation_members SET last_read_at = ? WHERE conversation_id = ? AND user_id = ?"
  ).run(Date.now(), req.params.id, req.userId);
  res.json({ ok: true });
});


/* -------------------------------------------------------------------------
   Socket.io 实时消息推送
   ------------------------------------------------------------------------- */
io.on("connection", (socket) => {

  // 客户端连接后第一件事:表明自己的身份,加入"个人房间"
  // 生产环境这里也要做真实的身份验证(校验 token),不能只信任前端传来的 userId
  socket.on("identify", (userId) => {
    socket.data.userId = userId;
    socket.join(`user:${userId}`);
  });

  // 发送消息
  socket.on("send_message", (payload, ack) => {
    const { conversationId, content, messageType } = payload;
    const senderId = socket.data.userId;
    if (!senderId) return ack && ack({ error: "未识别身份,请先调用 identify" });

    const isMember = db.prepare(
      "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?"
    ).get(conversationId, senderId);
    if (!isMember) return ack && ack({ error: "你不是该会话成员" });

    const message = {
      id: uuidv4(),
      conversation_id: conversationId,
      sender_id: senderId,
      content,
      message_type: messageType || "text",
      created_at: Date.now(),
    };

    db.prepare(`
      INSERT INTO messages (id, conversation_id, sender_id, content, message_type, created_at)
      VALUES (@id, @conversation_id, @sender_id, @content, @message_type, @created_at)
    `).run(message);

    // 把消息实时推给会话内所有成员(包括发送者自己的其他设备)
    const members = db.prepare(
      "SELECT user_id FROM conversation_members WHERE conversation_id = ?"
    ).all(conversationId);

    members.forEach(({ user_id }) => {
      io.to(`user:${user_id}`).emit("new_message", message);
    });

    ack && ack({ ok: true, message });
  });

  // 正在输入提示
  socket.on("typing", ({ conversationId }) => {
    const senderId = socket.data.userId;
    if (!senderId) return;
    const members = db.prepare(
      "SELECT user_id FROM conversation_members WHERE conversation_id = ? AND user_id != ?"
    ).all(conversationId, senderId);
    members.forEach(({ user_id }) => {
      io.to(`user:${user_id}`).emit("typing", { conversationId, userId: senderId });
    });
  });

  socket.on("disconnect", () => {
    // 预留:可在这里做"最后在线时间"更新等逻辑
  });
});


const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Loopa 后端服务已启动: http://localhost:${PORT}`);
  console.log(`PI_API_KEY 是否已正确读取: ${process.env.PI_API_KEY ? "是(长度" + process.env.PI_API_KEY.length + "位)" : "否 —— 未读取到,请检查 .env 文件"}`);
});
