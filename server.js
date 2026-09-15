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
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const db = require("./db");

// Cloudflare R2 是 S3 兼容的对象存储,用同一套 AWS SDK 就能对接,只是换了 endpoint
const r2 = new S3Client({
  region: "auto",
  endpoint: process.env.R2_ACCOUNT_ID ? `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : undefined,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || "",
  },
});

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
/* -------------------------------------------------------------------------
   账号同步接口:登录成功后,前端立刻调用这个接口,把 Pi/Google/Solana/BNB/
   手机号这几种登录身份,统一映射/绑定到同一个真实的平台账号(users表)上。

   ⚠️ 当前简化实现说明:这里直接信任前端传来的 externalId 就当作已验证的身份,
   跟 requireAuth() 里说的问题一样 —— 正式上线前必须先验证凭证真实性
   (校验 Pi accessToken / Google credential JWT / 钱包签名),再执行下面的
   查找或创建逻辑,不能像现在这样直接信任前端说的话。
   ------------------------------------------------------------------------- */
const PROVIDER_COLUMN = {
  pi: "pi_uid",
  google: "google_sub",
  solana: "solana_address",
  bnb: "bnb_address",
  phone: "phone_number",
};

app.post("/api/auth/sync", (req, res) => {
  const { provider, externalId, preferredUsername, avatarUrl, ageTier } = req.body;
  const column = PROVIDER_COLUMN[provider];
  if (!column || !externalId) {
    return res.status(400).json({ error: "provider 和 externalId 必填,provider 需为 pi/google/solana/bnb/phone 之一" });
  }

  // 先查这个身份是不是已经绑定过账号
  let user = db.prepare(`SELECT * FROM users WHERE ${column} = ?`).get(externalId);

  if (!user) {
    // 没有就新建一个账号,username 需要保证唯一,重名了就加个随机后缀
    const id = uuidv4();
    let username = (preferredUsername || `pioneer_${externalId.slice(0, 6)}`).toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const exists = db.prepare("SELECT 1 FROM users WHERE username = ?").get(username);
    if (exists) username = `${username}_${Math.floor(Math.random() * 9000 + 1000)}`;

    db.prepare(`
      INSERT INTO users (id, username, display_name, avatar_url, ${column}, age_tier, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, username, preferredUsername || username, avatarUrl || null, externalId, ageTier || null, Date.now());

    user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  } else if (ageTier && user.age_tier !== ageTier) {
    // 年龄分级信息如果有变化(比如首次同步时才拿到),顺手更新一下
    db.prepare("UPDATE users SET age_tier = ? WHERE id = ?").run(ageTier, user.id);
    user.age_tier = ageTier;
  }

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url,
    ageTier: user.age_tier,
  });
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

    // 把这笔"已批准"的打赏写入流水表,payment_id 唯一约束能防止 Pi SDK 自动重试导致重复插入
    try {
      db.prepare(`
        INSERT OR IGNORE INTO tips (id, payment_id, currency, amount, sender_uid, creator_name, memo, status, created_at)
        VALUES (?, ?, 'PI', ?, ?, ?, ?, 'approved', ?)
      `).run(
        uuidv4(),
        paymentId,
        payment.amount,
        payment.user_uid || null,
        payment.metadata?.creatorId || "unknown",
        payment.memo || null,
        Date.now()
      );
    } catch (dbErr) {
      // 数据库写入失败不应该导致整个支付批准失败(Pi那边已经批准了),但必须记日志,方便后续人工核对账目
      console.error("[Payment] ⚠️ 写入打赏流水表失败(不影响本次支付批准结果):", dbErr);
    }

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

    // 把流水表里这笔记录标记为"已完成",并原子性地累加创作者的收益汇总
    try {
      const tx = db.transaction(() => {
        const tip = db.prepare("SELECT amount, creator_name FROM tips WHERE payment_id = ?").get(paymentId);
        if (!tip) {
          // 理论上不应该发生(approve阶段应该已经插入过),但防御性处理一下
          console.error("[Payment] ⚠️ complete阶段找不到对应的流水记录,paymentId=", paymentId);
          return;
        }

        db.prepare(`
          UPDATE tips SET status = 'completed', tx_id = ?, completed_at = ? WHERE payment_id = ?
        `).run(txid, Date.now(), paymentId);

        db.prepare(`
          INSERT INTO creator_balances (creator_name, total_pi, tip_count, updated_at)
          VALUES (?, ?, 1, ?)
          ON CONFLICT(creator_name) DO UPDATE SET
            total_pi = total_pi + excluded.total_pi,
            tip_count = tip_count + 1,
            updated_at = excluded.updated_at
        `).run(tip.creator_name, tip.amount, Date.now());
      });
      tx();
    } catch (dbErr) {
      // 同上,数据库写入失败不应该让 Pi 那边已经确认完成的支付回滚,但必须留痕方便人工核对补账
      console.error("[Payment] ⚠️ 更新打赏流水/创作者收益失败(不影响本次支付完成结果):", dbErr);
    }

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 完成支付确认出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

// 查询某个创作者的累计打赏收益(个人主页"创作者收益"标签用)
app.get("/api/creators/:name/balance", (req, res) => {
  const { name } = req.params;
  const balance = db.prepare(
    "SELECT total_pi, tip_count, updated_at FROM creator_balances WHERE creator_name = ?"
  ).get(name);

  res.json(balance || { total_pi: 0, tip_count: 0, updated_at: null });
});


/* -------------------------------------------------------------------------
   视频上传与Feed接口

   上传流程采用"预签名直传"模式,不是把视频文件流经我们自己的服务器:
   1) 前端先调用 /api/videos/upload-url,拿到一个有时效性的R2直传地址
   2) 前端浏览器直接把视频文件 PUT 到这个地址(不经过我们的Node服务器)
   3) 上传完成后,前端再调用 /api/videos 把这条视频的信息(标题、地址等)存进数据库

   这样设计是因为我们的服务器配置很小(1核1GB),视频文件如果先经过它再转存,
   既占内存又占带宽,直传能完全绕开这个瓶颈,是视频类应用的标准做法。
   ------------------------------------------------------------------------- */

app.post("/api/videos/upload-url", async (req, res) => {
  const { filename, contentType } = req.body;
  if (!filename || !contentType) {
    return res.status(400).json({ error: "filename 和 contentType 必填" });
  }
  if (!process.env.R2_BUCKET_NAME || !process.env.R2_ACCOUNT_ID) {
    return res.status(500).json({ error: "服务端未配置 R2 存储,无法生成上传地址,请检查 .env" });
  }

  const videoId = uuidv4();
  const objectKey = `videos/${videoId}-${filename.replace(/[^a-zA-Z0-9._-]/g, "_")}`;

  try {
    const command = new PutObjectCommand({
      Bucket: process.env.R2_BUCKET_NAME,
      Key: objectKey,
      ContentType: contentType,
    });
    const uploadUrl = await getSignedUrl(r2, command, { expiresIn: 600 }); // 10分钟内有效

    const publicUrl = `${process.env.R2_PUBLIC_URL}/${objectKey}`;

    res.json({ videoId, uploadUrl, publicUrl });
  } catch (err) {
    console.error("[R2] 生成预签名上传地址失败:", err);
    res.status(500).json({ error: "生成上传地址失败" });
  }
});

app.post("/api/videos", (req, res) => {
  const { videoId, creatorId, creatorName, caption, videoUrl, thumbnailUrl } = req.body;
  if (!videoId || !creatorId || !creatorName || !videoUrl) {
    return res.status(400).json({ error: "videoId、creatorId、creatorName、videoUrl 均为必填" });
  }

  db.prepare(`
    INSERT INTO videos (id, creator_id, creator_name, caption, video_url, thumbnail_url, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'published', ?)
  `).run(videoId, creatorId, creatorName, caption || "", videoUrl, thumbnailUrl || null, Date.now());

  res.json({ ok: true, videoId });
});

// Feed流:按发布时间倒序,支持简单分页
app.get("/api/videos/feed", (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 20, 50);
  const before = Number(req.query.before) || Date.now();

  const videos = db.prepare(`
    SELECT id, creator_id, creator_name, caption, video_url, thumbnail_url, view_count, like_count, created_at
    FROM videos
    WHERE status = 'published' AND created_at < ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(before, limit);

  res.json(videos);
});

// 某个创作者自己发布过的作品(个人主页"作品"标签用)
app.get("/api/videos/user/:creatorId", (req, res) => {
  const videos = db.prepare(`
    SELECT id, caption, video_url, thumbnail_url, view_count, like_count, created_at
    FROM videos
    WHERE creator_id = ? AND status = 'published'
    ORDER BY created_at DESC
  `).all(req.params.creatorId);

  res.json(videos);
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
