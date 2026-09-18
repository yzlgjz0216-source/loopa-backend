/* =========================================================================
   server.js — Ownlo 后端服务(安全加固版)

   本地运行方式:
     1) cd loopa-backend
     2) npm install
     3) 复制 .env.example 为 .env,按里面的注释填好各项密钥
     4) npm start
   默认监听 http://localhost:4000

   ============================================================================
   本轮(安全加固)改动总览 —— 对应 GPT-6 审计报告 + Claude 复审发现的问题
   ============================================================================
   这是这一轮"审计问题优化"的核心文件,几乎每个接口都有改动,这里先总览,
   每个改动点在对应代码块上方还有更详细的注释(带 GPT-6/Claude 审计编号)。

   1. [P0] requireAuth 不再信任 x-user-id 请求头。现在前端登录/绑定成功后,
      服务端会签发一个短期 accessToken(自己实现的 HMAC-SHA256 签名令牌,
      结构和用法跟 JWT 等价,但零第三方依赖,见下面 signSession/verifySession),
      之后所有需要身份的请求都必须带 `Authorization: Bearer <accessToken>`,
      服务端验证签名和过期时间后才认这个身份 —— 伪造别人的 user-id 不再可能。
   2. [P0] Pi/Google/Solana/BNB 四种登录方式,本轮全部补上真实的服务端凭证校验:
        - Pi: 拿前端传来的 accessToken 去调 Pi 官方 GET /v2/me 验证,拿到的 uid
          才是真实身份,不再信任前端直接声明的 uid。
        - Google: 用 google-auth-library 验证 idToken 的签名和 audience,
          验证通过后取出 JWT 里的 sub 字段作为真实身份。
        - Solana/BNB: 采用标准的"挑战-签名"模式 —— 后端先发一个一次性随机
          消息(nonce),前端拿去用钱包签名,后端验证签名和地址匹配后才认
          这个钱包地址是真的。Solana 用 Node 原生 crypto 验证 Ed25519 签名
          (零依赖),BNB 用 ethers.verifyMessage 验证 ECDSA 签名。
      Google 因为还没有真实的 GOOGLE_CLIENT_ID(仍是占位符),本轮采用"失败
      关闭"策略:没配置就直接拒绝该登录方式的请求,不会把未验证的身份当真。
   3. [P0] 支付幂等性修复(GPT-6 P0-3):/api/payments/complete 用
      `UPDATE ... WHERE payment_id = ? AND status = 'approved'` 原子操作,
      只有真正把状态从 approved 改成 completed 的那一次请求(.changes === 1)
      才会给创作者加收益,Pi SDK 或用户手动重试都不会导致重复入账。
   4. [P1] 创作者收益不再按可变的显示名(creator_name)记账(GPT-6 P1-8):
      本轮把 creatorId 从前端一路串到后端,tips 表新增 creator_user_id、
      buyer_user_id、amount_units(整数)三个字段,creator_balances_v2 表
      按不可变的 creator_user_id 做主键。
   5. [P1] 所有写接口(点赞/关注/评论/改资料/发视频/拿上传地址)统一加上
      requireAuth,用服务端验证过的 req.userId 代替前端传来的 body.userId,
      彻底消除"冒充别人点赞/评论/改资料"的问题。
   6. [P1] Socket.io 从自由声明身份的 `identify` 事件改成连接握手阶段
      (`io.use` 中间件)验证 accessToken,验证不过直接拒绝连接。
   7. [P1] 限流:对认证、支付、上传、评论、发消息这几类敏感接口加了
      express-rate-limit,防止暴力枚举验证码、刷量、刷评论。
   8. [P1] CORS 不再是允许所有来源(`origin: "*"`),改成读取
      CORS_ALLOWED_ORIGINS 环境变量做白名单;Socket.io 的 cors 配置同步收紧。
   9. [P2] 年龄分级(age_tier)从"定义了但没人用"变成服务端真正读取并在
      打赏/私信接口里做限制(canTip / canReceiveTip / canDMFromStrangers)。
   10.[P2] 新增最基础的举报(reports)和拉黑(blocks)功能:举报写入表,
      等待人工处理;拉黑会从 Feed 里过滤对方的内容,并阻止双方建立新的私信会话。
   11.[P2] 关掉了本来打印全部请求路径的调试中间件(改成 DEBUG_REQUEST_LOG
      环境变量控制,默认关闭)。
   12.[P2] 视频审核开关(REQUIRE_VIDEO_REVIEW):打开后新发布的视频先进
      pending_review 状态,不进公开 Feed,需要用 ADMIN_TOKEN 调用审核接口通过。
      这只是一个最简易的"人工审核开关+一个接口",不是完整的后台管理系统,
      在交付说明里会明确写清楚这一点。

   ⚠️ 仍然明确告知、没有在本轮解决的问题(详见交付说明文档):
   - 手机验证码目前依然是"生成并落库,但没有接真实短信服务商"的演示状态,
     没有 Twilio/云片等账号无法真的发短信,这个接口设计已经就绪,接入真实
     短信 API 后即可切换成生产可用。
   - Google 登录在拿到真实 GOOGLE_CLIENT_ID 之前功能上不可用(会被服务端拒绝,
     这是有意为之的安全选择,而不是 bug)。
   - 视频审核只有开关和一个接口,没有可视化的后台管理界面。
   - 还没有做专业的第三方安全审计或压力测试,仍建议正式上线前找人复核一次。
   ========================================================================= */

require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { AccessToken: LiveKitAccessToken } = require("livekit-server-sdk");
const db = require("./db");

/* =========================================================================
   零依赖的会话令牌(HMAC-SHA256 签名,结构/用法等价于 JWT)

   本来计划用 jsonwebtoken 这个库,但开发沙箱环境的 npm registry 访问被拦截
   (403),没法安装任何第三方包来验证代码正确性。与其交付一段"看起来对但
   没实际跑过"的代码,不如用 Node 内置的 crypto 模块手写一个功能等价的最小
   实现 —— 这段逻辑已经在沙箱里用真实的签名/篡改/过期/错密钥四种场景跑过
   测试,全部按预期通过(见交付说明文档里的测试记录)。你的正式服务器有
   完整的网络访问,如果更倾向于用 jsonwebtoken,把下面这几个函数换成
   `jsonwebtoken` 的 sign/verify 调用即可,payload 结构完全兼容。
   ========================================================================= */
function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlToBuffer(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}
function signSession(payload, secret, ttlSeconds) {
  const header = { alg: "HS256", typ: "OWNLO" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + ttlSeconds };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(fullPayload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = crypto.createHmac("sha256", secret).update(signingInput).digest();
  return `${signingInput}.${base64url(sig)}`;
}
function verifySession(token, secret) {
  if (typeof token !== "string") throw new Error("malformed token");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;
  const expectedSig = crypto.createHmac("sha256", secret).update(signingInput).digest();
  const actualSig = base64urlToBuffer(sigB64);
  if (expectedSig.length !== actualSig.length || !crypto.timingSafeEqual(expectedSig, actualSig)) {
    throw new Error("bad signature");
  }
  const payload = JSON.parse(base64urlToBuffer(payloadB64).toString("utf8"));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) throw new Error("expired");
  return payload;
}

/* -------------------------------------------------------------------------
   零依赖的 Solana Ed25519 签名验证(base58 编解码 + Node 原生 crypto.verify)
   同样是因为沙箱里没法安装 tweetnacl / bs58 验证代码正确性,改用 Node 内置
   crypto 模块 + SPKI DER 包装技巧实现,已在沙箱里用真实生成的密钥对测试过
   "正确签名通过 / 篡改消息拒绝 / 错误公钥拒绝"三种场景,全部符合预期。
   ------------------------------------------------------------------------- */
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = {};
for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = i;

function base58Decode(str) {
  let bytes = [0];
  for (const ch of str) {
    const value = B58_MAP[ch];
    if (value === undefined) throw new Error(`invalid base58 char: ${ch}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of str) {
    if (ch === "1") bytes.push(0);
    else break;
  }
  return Buffer.from(bytes.reverse());
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function verifyEd25519(messageBytes, signatureBytes, rawPublicKeyBytes) {
  if (rawPublicKeyBytes.length !== 32) throw new Error("Solana public key must be 32 bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKeyBytes]);
  const keyObject = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  return crypto.verify(null, messageBytes, keyObject, signatureBytes);
}

// BNB(EVM)链签名验证走 ethers,标准 ECDSA recover,沙箱里没法装 ethers 验证,
// 但这是 ethers 文档里最基础的 API,风险很低;用不到时懒加载,避免 Google/Solana
// 专用环境下也强制要求装上 ethers。
let _ethers = null;
function getEthers() {
  if (!_ethers) _ethers = require("ethers");
  return _ethers;
}

// Google idToken 验证同理懒加载,只有真正配置了 GOOGLE_CLIENT_ID 才会用到。
let _googleClient = null;
function getGoogleClient() {
  if (!_googleClient) {
    const { OAuth2Client } = require("google-auth-library");
    _googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }
  return _googleClient;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/* -------------------------------------------------------------------------
   必需的环境变量校验:SESSION_SECRET 是签发/验证所有登录令牌的根密钥,
   如果没配置、或者还是默认占位符,绝不能启动服务 —— 否则等于任何人都能
   伪造一个自己签名验证得过的"登录令牌",是比没有认证更危险的情况。
   ------------------------------------------------------------------------- */
const SESSION_SECRET = process.env.SESSION_SECRET || "";
if (!SESSION_SECRET || SESSION_SECRET.length < 16) {
  console.error(
    "[启动失败] 必须在 .env 里配置一个足够长(建议32位以上随机字符串)的 SESSION_SECRET," +
    "这是签发登录令牌用的根密钥,绝不能留空或用默认值。可以用命令" +
    ' `node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"` 生成一个。'
  );
  process.exit(1);
}

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15分钟
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30天
const REQUIRE_VIDEO_REVIEW = String(process.env.REQUIRE_VIDEO_REVIEW || "").toLowerCase() === "true";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

// 直播功能(本轮新增,Phase 0 技术验证优先接入 LiveKit):三个变量任一没配置,
// /api/livestreams/* 接口会直接返回 503,不会让服务整体崩溃启动失败——
// 直播是可选功能,没配置密钥之前不影响其它功能正常使用。
const LIVEKIT_URL = process.env.LIVEKIT_URL || "";
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY || "";
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET || "";
async function buildLiveKitToken(identity, displayName, roomName, { canPublish }) {
  const at = new LiveKitAccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity,
    name: displayName || identity,
    ttl: "6h",
  });
  at.addGrant({
    room: roomName,
    roomJoin: true,
    canPublish: !!canPublish,
    canPublishData: true, // 用于以后如果要用 LiveKit 自带的数据通道做礼物动效同步(Phase 4)
    canSubscribe: true,
  });
  return at.toJwt();
}

// Cloudflare R2 是 S3 兼容的对象存储,用同一套 AWS SDK 就能对接,只是换了 endpoint
const r2 = new S3Client({
  region: "auto",
  endpoint: process.env.R2_ACCOUNT_ID ? `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : undefined,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || "",
  },
});

/* -------------------------------------------------------------------------
   邮箱验证码发送(接入真实服务商:Resend)。手机验证码复用同一套
   verification_codes 表结构,但目前没有接短信服务商,发送时只落库+打印日志
   (明确的演示状态,详见交付说明文档)。
   ------------------------------------------------------------------------- */
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "Ownlo <no-reply@ownlo.app>";
const CODE_TTL_MS = 10 * 60 * 1000; // 验证码10分钟内有效
const CODE_MAX_ATTEMPTS = 5; // 超过5次错误尝试直接作废,防止暴力枚举6位数字

async function sendVerificationEmail(toEmail, code) {
  if (!RESEND_API_KEY) {
    console.warn(`[Email] 未配置 RESEND_API_KEY,验证码不会真的发出去,仅打印到日志 —— ${toEmail}: ${code}`);
    return { demo: true };
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [toEmail],
      subject: "你的 Ownlo 验证码",
      html: `<div style="font-family:sans-serif;font-size:15px;color:#222">
        <p>你正在 Ownlo 验证这个邮箱地址,验证码是:</p>
        <p style="font-size:26px;font-weight:700;letter-spacing:4px">${code}</p>
        <p style="color:#888">10分钟内有效。如果这不是你本人的操作,忽略这封邮件即可,不会有任何影响。</p>
      </div>`,
    }),
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Resend 发送失败: ${response.status} ${errText}`);
  }
  return response.json();
}

function sendVerificationSMS(phoneNumber, code) {
  // 演示状态:没有接入真实短信服务商(如 Twilio / 云片)。这里只打印日志,
  // 方便你在没有短信账号之前继续联调其它功能。接入真实服务商时,把这个函数
  // 换成对应 SDK 的发送调用即可,上层的验证码校验逻辑不用改。
  console.warn(`[SMS] 未接入真实短信服务商,验证码不会真的发出去,仅打印到日志 —— ${phoneNumber}: ${code}`);
  return Promise.resolve({ demo: true });
}

/* -------------------------------------------------------------------------
   Express / CORS / Socket.io 初始化
   ------------------------------------------------------------------------- */
const app = express();

// CORS 白名单:生产环境必须在 .env 配置 CORS_ALLOWED_ORIGINS(逗号分隔的
// 允许来源列表,比如 https://ownlo.app,https://www.ownlo.app)。没配置时
// 为了不阻断本地开发,退化成允许所有来源,但会在启动时打印醒目警告。
const allowedOrigins = String(process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (allowedOrigins.length === 0) {
  console.warn(
    "[启动警告] 未配置 CORS_ALLOWED_ORIGINS,当前允许任意来源跨域请求(仅适合本地开发)。" +
    "正式上线前请在 .env 里配置真实的前端域名,比如 https://ownlo.app"
  );
}

const corsOptions = {
  origin(origin, callback) {
    // 允许没有 Origin 头的请求(比如服务端到服务端调用、curl、健康检查)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true); // 未配置时退化放行,见上面警告
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS 拒绝:来源 ${origin} 不在白名单里`));
  },
};
app.use(cors(corsOptions));
app.use(express.json());

// 本轮新增:背景音乐曲库静态目录——这几首都是随代码一起打包的、纯合成生成的
// 原创免版权音乐(见 db.js 里 music_tracks 种子数据的注释),文件不大,直接从
// 后端本地磁盘提供即可,不需要额外配置 R2/对象存储就能用。
app.use("/music", express.static(path.join(__dirname, "public", "music")));

// 调试用的全量请求日志,默认关闭(避免生产环境日志里堆满噪音,也避免
// 意外把带敏感信息的请求路径打进日志),需要时在 .env 设置 DEBUG_REQUEST_LOG=true
if (String(process.env.DEBUG_REQUEST_LOG || "").toLowerCase() === "true") {
  app.use((req, res, next) => {
    console.log(`[请求日志] ${req.method} ${req.path}`);
    next();
  });
}

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: allowedOrigins.length > 0 ? allowedOrigins : true,
  },
});

/* -------------------------------------------------------------------------
   限流:对容易被刷的敏感接口分别配置 express-rate-limit。
   ------------------------------------------------------------------------- */
function makeLimiter(windowMs, max, message) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
  });
}
const authLimiter = makeLimiter(15 * 60 * 1000, 20, "请求过于频繁,请15分钟后再试");
const codeLimiter = makeLimiter(10 * 60 * 1000, 5, "验证码请求过于频繁,请10分钟后再试");
const paymentLimiter = makeLimiter(60 * 1000, 20, "支付请求过于频繁,请稍后再试");
const uploadLimiter = makeLimiter(60 * 60 * 1000, 30, "上传请求过于频繁,请稍后再试");
const commentLimiter = makeLimiter(60 * 1000, 20, "评论发送过于频繁,请稍后再试");

/* -------------------------------------------------------------------------
   requireAuth:验证 Authorization: Bearer <accessToken>,不再信任任何
   客户端自称的身份字段(x-user-id / body.userId 等全部废弃)。
   ------------------------------------------------------------------------- */
function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const match = /^Bearer\s+(.+)$/.exec(header);
  if (!match) return res.status(401).json({ error: "缺少登录令牌,请先登录", code: "NO_TOKEN" });

  let payload;
  try {
    payload = verifySession(match[1], SESSION_SECRET);
  } catch (e) {
    // 区分"过期"和"其它无效"两种情况,方便前端在过期时自动尝试用 refreshToken 刷新
    const expired = e.message === "expired";
    return res.status(401).json({ error: expired ? "登录已过期,请刷新令牌" : "登录令牌无效", code: expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID" });
  }

  const user = db.prepare("SELECT id FROM users WHERE id = ?").get(payload.sub);
  if (!user) return res.status(401).json({ error: "账号不存在或已被删除", code: "USER_NOT_FOUND" });

  req.userId = payload.sub;
  next();
}

// 可选身份验证:有 token 就解析出 userId,没有或无效也不报错(用于一些
// "登录与否都能访问,但登录了会有额外信息"的接口,目前 Feed 相关接口会用到)
function optionalAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const match = /^Bearer\s+(.+)$/.exec(header);
  if (!match) return next();
  try {
    const payload = verifySession(match[1], SESSION_SECRET);
    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(payload.sub);
    if (user) req.userId = payload.sub;
  } catch (e) {
    // 忽略无效token,当成未登录处理
  }
  next();
}

function issueTokenPair(userId) {
  const accessToken = signSession({ sub: userId }, SESSION_SECRET, ACCESS_TOKEN_TTL_SECONDS);
  const refreshToken = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  db.prepare(`
    INSERT INTO refresh_tokens (id, user_id, token_hash, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(uuidv4(), userId, sha256Hex(refreshToken), now, now + REFRESH_TOKEN_TTL_MS);
  return { accessToken, refreshToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS };
}

// 本轮新增:统一的"发一条通知"辅助函数——有人赞了/评论了/关注了/打赏了你,
// 或者平台方要发系统公告,都通过它写进 notifications 表。特意加了两个防噪音的判断:
// 不给自己发通知(比如自己给自己的作品点赞、自己评论自己的作品,这种不需要提醒);
// 系统公告(type='system')允许 actorId 为空。
function createNotification({ userId, type, actorId = null, videoId = null, content = null }) {
  if (!userId) return;
  if (actorId && actorId === userId) return; // 不给自己发通知
  db.prepare(`
    INSERT INTO notifications (id, user_id, type, actor_id, video_id, content, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(uuidv4(), userId, type, actorId, videoId, content, Date.now());
}

function publicUserView(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url,
    backgroundUrl: user.background_url, // 本轮新增:个人资料背景图
    ageTier: user.age_tier,
    bio: user.bio || "",
  };
}

/* -------------------------------------------------------------------------
   年龄分级限制(GPT-6审计:TEEN_MODE_RESTRICTIONS 之前只在前端定义,从未被
   服务端真正读取和执行 —— 任何人绕过前端直接调接口就能完全无视这些限制)。
   这里先落地最基础的几条,和前端 app.js 里原有的 TEEN_MODE_RESTRICTIONS
   对应,具体分级值以 users.age_tier 里存的字符串为准(比如 'teen'/'adult')。
   ------------------------------------------------------------------------- */
function canTip(ageTier) {
  return ageTier !== "teen"; // 未成年账号不能打赏出去
}
function canReceiveTip(ageTier) {
  return ageTier !== "teen"; // 未成年账号不能接收打赏
}
function canDMFromStrangers(ageTier) {
  return ageTier !== "teen"; // 未成年账号只能被已关注的人私信(见下面用法)
}

/* =========================================================================
   账号登录 / 绑定
   ========================================================================= */
const PROVIDER_COLUMN = {
  pi: "pi_uid",
  google: "google_sub",
  solana: "solana_address",
  bnb: "bnb_address",
  phone: "phone_number",
};
const BIND_PROVIDER_COLUMN = { ...PROVIDER_COLUMN, email: "email" };

function findOrCreateUser({ column, externalId, preferredUsername, avatarUrl, ageTier }) {
  let user = db.prepare(`SELECT * FROM users WHERE ${column} = ?`).get(externalId);
  if (!user) {
    const id = uuidv4();
    let username = (preferredUsername || `pioneer_${String(externalId).slice(0, 6)}`).toLowerCase().replace(/[^a-z0-9_]/g, "_") || `pioneer_${id.slice(0, 6)}`;
    const exists = db.prepare("SELECT 1 FROM users WHERE username = ?").get(username);
    if (exists) username = `${username}_${Math.floor(Math.random() * 9000 + 1000)}`;
    db.prepare(`
      INSERT INTO users (id, username, display_name, avatar_url, ${column}, age_tier, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, username, preferredUsername || username, avatarUrl || null, externalId, ageTier || null, Date.now());
    user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  } else if (ageTier && user.age_tier !== ageTier) {
    db.prepare("UPDATE users SET age_tier = ? WHERE id = ?").run(ageTier, user.id);
    user.age_tier = ageTier;
  }
  return user;
}

// 钱包登录/绑定第一步:申请一次性挑战消息(nonce)
app.post("/api/auth/challenge", authLimiter, (req, res) => {
  const { provider, address } = req.body || {};
  if (!["solana", "bnb"].includes(provider) || !address) {
    return res.status(400).json({ error: "provider 必须是 solana 或 bnb,address 必填" });
  }
  const id = uuidv4();
  const now = Date.now();
  const message = `Sign this message to prove you own this ${provider === "solana" ? "Solana" : "BNB"} wallet and log in to Ownlo.\n\nNonce: ${id}\nIssued at: ${new Date(now).toISOString()}`;
  db.prepare(`
    INSERT INTO auth_challenges (id, provider, address, message, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, provider, address, message, now, now + 5 * 60 * 1000); // 5分钟内有效
  res.json({ challengeId: id, message });
});

function consumeWalletChallenge({ provider, address, signature, challengeId }) {
  const challenge = db.prepare("SELECT * FROM auth_challenges WHERE id = ?").get(challengeId);
  if (!challenge) throw new Error("挑战消息不存在或已过期,请重新发起登录");
  if (challenge.consumed_at) throw new Error("这条挑战消息已经被使用过,请重新发起登录");
  if (Date.now() > challenge.expires_at) throw new Error("挑战消息已过期,请重新发起登录");
  if (challenge.provider !== provider || challenge.address !== address) {
    throw new Error("挑战消息与当前请求的 provider/address 不匹配");
  }

  const messageBytes = Buffer.from(challenge.message, "utf8");

  if (provider === "solana") {
    const sigBytes = base58Decode(signature);
    const pubKeyBytes = base58Decode(address);
    const ok = verifyEd25519(messageBytes, sigBytes, pubKeyBytes);
    if (!ok) throw new Error("Solana 钱包签名验证失败,请确认签名和地址是否匹配");
  } else if (provider === "bnb") {
    const { verifyMessage } = getEthers();
    let recovered;
    try {
      recovered = verifyMessage(challenge.message, signature);
    } catch (e) {
      throw new Error("BNB 钱包签名格式无效");
    }
    if (recovered.toLowerCase() !== address.toLowerCase()) {
      throw new Error("BNB 钱包签名验证失败,恢复出的地址与声明的地址不匹配");
    }
  }

  db.prepare("UPDATE auth_challenges SET consumed_at = ? WHERE id = ?").run(Date.now(), challengeId);
}

async function verifyPiAccessToken(piAccessToken) {
  const response = await fetch("https://api.minepi.com/v2/me", {
    headers: { Authorization: `Bearer ${piAccessToken}` },
  });
  if (!response.ok) throw new Error("Pi accessToken 验证失败,请重新登录 Pi 账号");
  const data = await response.json();
  if (!data || !data.uid) throw new Error("Pi 官方接口返回数据异常");
  return data.uid;
}

async function verifyGoogleIdToken(idToken) {
  if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID.includes("YOUR_GOOGLE")) {
    throw new Error("服务端尚未配置真实的 GOOGLE_CLIENT_ID,Google 登录暂不可用");
  }
  const client = getGoogleClient();
  const ticket = await client.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();
  if (!payload || !payload.sub) throw new Error("Google idToken 验证失败");
  return payload;
}

/* -------------------------------------------------------------------------
   登录/自动建号接口。本轮起,四种第三方身份(pi/google/solana/bnb)全部
   要求带上"可验证的凭证"而不是直接声明的 externalId:
     - pi:    { provider:'pi', piAccessToken }
     - google:{ provider:'google', idToken }
     - solana/bnb: { provider, address, signature, challengeId }(需先调用
       /api/auth/challenge 拿到 challengeId)
     - phone: { provider:'phone', phoneNumber, code }(需先调用
       /api/auth/send-code 且 channel=phone 拿到验证码)
   验证通过后才会执行 find-or-create 逻辑,返回 accessToken/refreshToken。
   ------------------------------------------------------------------------- */
app.post("/api/auth/sync", authLimiter, async (req, res) => {
  const { provider, preferredUsername, avatarUrl, ageTier } = req.body || {};
  try {
    let externalId;
    if (provider === "pi") {
      if (!req.body.piAccessToken) return res.status(400).json({ error: "piAccessToken 必填" });
      externalId = await verifyPiAccessToken(req.body.piAccessToken);
    } else if (provider === "google") {
      if (!req.body.idToken) return res.status(400).json({ error: "idToken 必填" });
      const payload = await verifyGoogleIdToken(req.body.idToken);
      externalId = payload.sub;
    } else if (provider === "solana" || provider === "bnb") {
      const { address, signature, challengeId } = req.body;
      if (!address || !signature || !challengeId) {
        return res.status(400).json({ error: "address、signature、challengeId 均为必填" });
      }
      consumeWalletChallenge({ provider, address, signature, challengeId });
      externalId = address;
    } else if (provider === "phone") {
      const { phoneNumber, code } = req.body;
      if (!phoneNumber || !code) return res.status(400).json({ error: "phoneNumber 和 code 均为必填" });
      verifyAndConsumeCode({ channel: "phone", identifier: phoneNumber, code });
      externalId = phoneNumber;
    } else {
      return res.status(400).json({ error: "provider 需为 pi/google/solana/bnb/phone 之一" });
    }

    const column = PROVIDER_COLUMN[provider];
    const user = findOrCreateUser({ column, externalId, preferredUsername, avatarUrl, ageTier });
    const tokens = issueTokenPair(user.id);
    res.json({ ...publicUserView(user), ...tokens });
  } catch (err) {
    console.error(`[auth/sync] provider=${provider} 验证失败:`, err.message);
    res.status(401).json({ error: err.message || "身份验证失败" });
  }
});

/* -------------------------------------------------------------------------
   开发调试专用登录接口(本轮新增,默认关闭,fail-closed)。

   背景:本轮把登录全部改成要求真实凭证之后,在普通电脑浏览器里(不在 Pi
   Browser 里、没装 Phantom/MetaMask 插件)本地调试界面时,四种第三方登录
   都会因为拿不到真实凭证而在服务端被拒绝——这是正确的安全行为,但会导致
   开发者连界面都进不去、没法预览。

   这个接口就是专门给"本地/测试环境预览界面用"的后门:必须在 .env 里显式
   设置 ALLOW_DEV_LOGIN=true 才会生效,默认(不设置或设置成任何其它值)一律
   拒绝。正式环境的 .env 绝对不能打开这个开关——一旦打开,任何知道这个
   接口存在的人都可以无需任何凭证、直接冒充/创建任意账号登录,等于完全
   没有身份验证。这一点在 .env.example 里也会用醒目的注释再次强调。
   ------------------------------------------------------------------------- */
app.post("/api/auth/dev-login", authLimiter, (req, res) => {
  if (String(process.env.ALLOW_DEV_LOGIN || "").toLowerCase() !== "true") {
    return res.status(403).json({ error: "开发登录接口未启用(ALLOW_DEV_LOGIN 不是 true),生产环境请勿开启此项" });
  }
  console.warn(`[⚠️ 安全警告] 有请求使用了免验证的开发登录接口 /api/auth/dev-login,` +
    `provider=${req.body?.provider}。这个接口不做任何真实身份校验,` +
    `如果你在生产环境看到这条日志,说明 ALLOW_DEV_LOGIN 被错误地打开了,请立刻关闭。`);

  const { provider, externalId, preferredUsername, avatarUrl, ageTier } = req.body || {};
  const column = PROVIDER_COLUMN[provider];
  if (!column || !externalId) {
    return res.status(400).json({ error: "provider 和 externalId 必填" });
  }
  const user = findOrCreateUser({ column, externalId: `dev:${externalId}`, preferredUsername, avatarUrl, ageTier });
  const tokens = issueTokenPair(user.id);
  res.json({ ...publicUserView(user), ...tokens });
});

// 给邮箱/手机号发一次性验证码,channel 区分渠道,identifier 是邮箱地址或手机号
app.post("/api/auth/send-code", codeLimiter, async (req, res) => {
  const channel = req.body?.channel === "phone" ? "phone" : "email";
  let identifier = String(req.body?.identifier ?? req.body?.email ?? req.body?.phoneNumber ?? "").trim();
  if (channel === "email") {
    identifier = identifier.toLowerCase();
    if (!identifier || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) {
      return res.status(400).json({ error: "请输入有效的邮箱地址" });
    }
  } else {
    if (!identifier || identifier.replace(/[^0-9]/g, "").length < 6) {
      return res.status(400).json({ error: "请输入有效的手机号" });
    }
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const now = Date.now();
  db.prepare(`
    INSERT INTO verification_codes (id, channel, identifier, code_hash, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(uuidv4(), channel, identifier, sha256Hex(code), now, now + CODE_TTL_MS);

  try {
    if (channel === "email") await sendVerificationEmail(identifier, code);
    else await sendVerificationSMS(identifier, code);
    res.json({ ok: true });
  } catch (err) {
    console.error(`[send-code] 发送失败 (${channel}):`, err);
    res.status(502).json({ error: "验证码发送失败,请稍后重试" });
  }
});

// 校验一个验证码是否有效,验证通过后立刻标记消费(一次性使用),超过错误
// 次数上限直接作废,防止有人对着同一个邮箱/手机号暴力枚举6位数字。
function verifyAndConsumeCode({ channel, identifier, code }) {
  const normalizedId = channel === "email" ? String(identifier).trim().toLowerCase() : String(identifier).trim();
  const record = db.prepare(`
    SELECT * FROM verification_codes
    WHERE channel = ? AND identifier = ? AND consumed_at IS NULL
    ORDER BY created_at DESC LIMIT 1
  `).get(channel, normalizedId);

  if (!record) throw new Error("请先获取验证码");
  if (Date.now() > record.expires_at) throw new Error("验证码已过期,请重新获取");
  if (record.attempts >= CODE_MAX_ATTEMPTS) throw new Error("错误次数过多,验证码已作废,请重新获取");

  const codeHash = sha256Hex(String(code || ""));
  const match = codeHash.length === record.code_hash.length && crypto.timingSafeEqual(Buffer.from(codeHash), Buffer.from(record.code_hash));
  if (!match) {
    db.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?").run(record.id);
    throw new Error("验证码错误");
  }
  db.prepare("UPDATE verification_codes SET consumed_at = ? WHERE id = ?").run(Date.now(), record.id);
}

/* -------------------------------------------------------------------------
   账号绑定接口:给已登录账号追加绑定一种新的身份。本轮起,pi/google/
   solana/bnb/phone 这五种也都要求真实凭证(和 /api/auth/sync 同一套校验
   逻辑),邮箱沿用上一轮已经接好的真实验证码校验。
   ------------------------------------------------------------------------- */
app.post("/api/auth/bind", requireAuth, authLimiter, async (req, res) => {
  const { provider } = req.body || {};
  const column = BIND_PROVIDER_COLUMN[provider];
  if (!column) return res.status(400).json({ error: "provider 需为 pi/google/solana/bnb/phone/email 之一" });

  let normalizedId;
  try {
    if (provider === "pi") {
      if (!req.body.piAccessToken) return res.status(400).json({ error: "piAccessToken 必填" });
      normalizedId = await verifyPiAccessToken(req.body.piAccessToken);
    } else if (provider === "google") {
      if (!req.body.idToken) return res.status(400).json({ error: "idToken 必填" });
      normalizedId = (await verifyGoogleIdToken(req.body.idToken)).sub;
    } else if (provider === "solana" || provider === "bnb") {
      const { address, signature, challengeId } = req.body;
      if (!address || !signature || !challengeId) {
        return res.status(400).json({ error: "address、signature、challengeId 均为必填" });
      }
      consumeWalletChallenge({ provider, address, signature, challengeId });
      normalizedId = address;
    } else if (provider === "phone") {
      const { phoneNumber, code } = req.body;
      if (!phoneNumber || !code) return res.status(400).json({ error: "phoneNumber 和 code 均为必填" });
      verifyAndConsumeCode({ channel: "phone", identifier: phoneNumber, code });
      normalizedId = phoneNumber;
    } else if (provider === "email") {
      const { externalId, code } = req.body;
      if (!externalId) return res.status(400).json({ error: "externalId(邮箱地址)必填" });
      verifyAndConsumeCode({ channel: "email", identifier: externalId, code });
      normalizedId = String(externalId).trim().toLowerCase();
    }
  } catch (err) {
    return res.status(400).json({ error: err.message || "身份验证失败" });
  }

  if (!normalizedId) return res.status(400).json({ error: "缺少必要的身份信息" });

  // 数据库层的部分唯一索引是最终防线(见 db.js),这里的查询是为了给出更友好的错误信息。
  const existingOwner = db.prepare(`SELECT id FROM users WHERE ${column} = ?`).get(normalizedId);
  if (existingOwner && existingOwner.id !== req.userId) {
    return res.status(409).json({ error: "这个身份已经绑定在另一个 Ownlo 账号上了,不能重复绑定" });
  }
  if (existingOwner && existingOwner.id === req.userId) {
    return res.json({ ok: true, alreadyBound: true, bindings: getBindingsForUser(req.userId) });
  }

  try {
    db.prepare(`UPDATE users SET ${column} = ? WHERE id = ?`).run(normalizedId, req.userId);
  } catch (e) {
    // 兜底:并发场景下可能刚好撞上数据库唯一索引(见 db.js 的 idx_users_* 部分唯一索引)
    if (/UNIQUE constraint failed/i.test(e.message)) {
      return res.status(409).json({ error: "这个身份已经绑定在另一个 Ownlo 账号上了,不能重复绑定" });
    }
    throw e;
  }

  res.json({ ok: true, alreadyBound: false, bindings: getBindingsForUser(req.userId) });
});

// 查询某个账号目前绑定了哪些身份(只返回布尔值,不返回具体的邮箱/手机号/钱包地址原文)
app.get("/api/users/:id/bindings", requireAuth, (req, res) => {
  // 本轮改为要求登录:之前任何人都能查任意用户绑了哪些身份类型,虽然不返回
  // 具体号码,但"某人是否绑定了手机号/邮箱"本身也是不该完全公开的信息,
  // 收紧为只有本人可查。
  if (req.params.id !== req.userId) return res.status(403).json({ error: "只能查询自己的绑定状态" });
  res.json(getBindingsForUser(req.params.id));
});

function getBindingsForUser(userId) {
  const row = db.prepare(
    "SELECT pi_uid, google_sub, solana_address, bnb_address, phone_number, email FROM users WHERE id = ?"
  ).get(userId);
  if (!row) return { pi: false, google: false, solana: false, bnb: false, phone: false, email: false };
  return {
    pi: !!row.pi_uid, google: !!row.google_sub, solana: !!row.solana_address,
    bnb: !!row.bnb_address, phone: !!row.phone_number, email: !!row.email,
  };
}

// 刷新令牌:accessToken 过期后,前端用 refreshToken 换一对新的令牌(轮换机制,
// 旧的 refreshToken 立刻失效,防止一个泄露的 refreshToken 被反复使用)。
app.post("/api/auth/refresh", authLimiter, (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: "refreshToken 必填" });

  const hash = sha256Hex(refreshToken);
  const record = db.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?").get(hash);
  if (!record || record.revoked_at || Date.now() > record.expires_at) {
    return res.status(401).json({ error: "refreshToken 无效或已过期,请重新登录" });
  }

  const tokens = issueTokenPair(record.user_id);
  db.prepare("UPDATE refresh_tokens SET revoked_at = ?, replaced_by = ? WHERE id = ?")
    .run(Date.now(), tokens.refreshToken, record.id);

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(record.user_id);
  if (!user) return res.status(401).json({ error: "账号不存在" });
  res.json({ ...publicUserView(user), ...tokens });
});

app.post("/api/auth/logout", (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    db.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
      .run(Date.now(), sha256Hex(refreshToken));
  }
  res.json({ ok: true });
});

/* =========================================================================
   Pi 支付接口
   ========================================================================= */
const PI_API_BASE = "https://api.minepi.com/v2";

app.post("/api/payments/approve", requireAuth, paymentLimiter, async (req, res) => {
  const { paymentId, creatorId } = req.body;
  if (!paymentId) return res.status(400).json({ error: "paymentId 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Payment] ⚠️ PI_API_KEY 未配置,无法调用 Pi 官方 API,批准请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  // 年龄分级限制(GPT-6审计:之前 TEEN_MODE_RESTRICTIONS 只在前端定义,服务端从未真正执行)
  const buyer = db.prepare("SELECT age_tier FROM users WHERE id = ?").get(req.userId);
  if (buyer && !canTip(buyer.age_tier)) {
    return res.status(403).json({ error: "当前账号年龄分级不允许发起打赏" });
  }

  let creatorUserId = null;
  let creatorName = "unknown";
  if (creatorId) {
    const creator = db.prepare("SELECT id, username, age_tier FROM users WHERE id = ?").get(creatorId);
    if (creator) {
      if (!canReceiveTip(creator.age_tier)) {
        return res.status(403).json({ error: "对方账号年龄分级不允许接收打赏" });
      }
      creatorUserId = creator.id;
      creatorName = creator.username;
    }
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/approve`, {
      method: "POST",
      headers: { Authorization: `Key ${process.env.PI_API_KEY}` },
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 批准支付失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 批准失败", detail: errText });
    }
    const payment = await response.json();

    try {
      const amountUnits = Math.round(Number(payment.amount) * 10000000);
      db.prepare(`
        INSERT OR IGNORE INTO tips
          (id, payment_id, currency, amount, amount_units, buyer_user_id, creator_user_id, creator_name, memo, status, created_at)
        VALUES (?, ?, 'PI', ?, ?, ?, ?, ?, ?, 'approved', ?)
      `).run(
        uuidv4(), paymentId, payment.amount, amountUnits, req.userId,
        creatorUserId, payment.metadata?.creatorName || creatorName, payment.memo || null, Date.now()
      );
    } catch (dbErr) {
      console.error("[Payment] ⚠️ 写入打赏流水表失败(不影响本次支付批准结果):", dbErr);
    }

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 批准支付出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

app.post("/api/payments/complete", requireAuth, paymentLimiter, async (req, res) => {
  const { paymentId, txid } = req.body;
  if (!paymentId || !txid) return res.status(400).json({ error: "paymentId 和 txid 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Payment] ⚠️ PI_API_KEY 未配置,无法调用 Pi 官方 API,完成请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/complete`, {
      method: "POST",
      headers: { Authorization: `Key ${process.env.PI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ txid }),
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 完成支付确认失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 完成确认失败", detail: errText });
    }
    const payment = await response.json();

    // ⚠️ 支付幂等性核心修复(GPT-6 P0-3):用原子的
    // "UPDATE ... WHERE status='approved'" 加 .changes 判断,只有真正把状态
    // 从 approved 改成 completed 的那一次调用才会执行下面的收益累加,
    // Pi SDK 自动重试或用户手动重复点击都不会导致同一笔打赏被重复计入创作者收益。
    try {
      const tx = db.transaction(() => {
        const updateResult = db.prepare(
          "UPDATE tips SET status = 'completed', tx_id = ?, completed_at = ? WHERE payment_id = ? AND status = 'approved'"
        ).run(txid, Date.now(), paymentId);

        if (updateResult.changes !== 1) {
          console.warn(`[Payment] paymentId=${paymentId} 不是首次 complete(可能是重试),跳过收益累加,这是预期行为`);
          return;
        }

        const tip = db.prepare("SELECT amount, amount_units, creator_user_id, creator_name, buyer_user_id FROM tips WHERE payment_id = ?").get(paymentId);
        if (!tip) return;

        // 旧表(按显示名),继续写入只作历史兼容展示
        db.prepare(`
          INSERT INTO creator_balances (creator_name, total_pi, tip_count, updated_at)
          VALUES (?, ?, 1, ?)
          ON CONFLICT(creator_name) DO UPDATE SET
            total_pi = total_pi + excluded.total_pi, tip_count = tip_count + 1, updated_at = excluded.updated_at
        `).run(tip.creator_name, tip.amount, Date.now());

        // 新表(按不可变 creator_user_id),真正的记账依据
        if (tip.creator_user_id) {
          db.prepare(`
            INSERT INTO creator_balances_v2 (creator_user_id, creator_name, total_pi_units, tip_count, updated_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(creator_user_id) DO UPDATE SET
              creator_name = excluded.creator_name,
              total_pi_units = total_pi_units + excluded.total_pi_units,
              tip_count = tip_count + 1,
              updated_at = excluded.updated_at
          `).run(tip.creator_user_id, tip.creator_name, tip.amount_units || 0, Date.now());
        }

        // 打赏到账,给创作者发一条通知(本轮新增)。
        if (tip.creator_user_id) {
          createNotification({
            userId: tip.creator_user_id, type: "tip", actorId: tip.buyer_user_id || null,
            content: `收到 ${tip.amount} PI 打赏`,
          });
        }
      });
      tx();
    } catch (dbErr) {
      console.error("[Payment] ⚠️ 更新打赏流水/创作者收益失败(不影响本次支付完成结果):", dbErr);
    }

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 完成支付确认出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

// 本轮新增:直接按账号 ID 查创作者收益——之前只有按"名字"查的 /api/creators/:name/balance,
// 前端实际传的是可以改的昵称(displayName),不是不会变的 username,两者一旦不一致就查
// 不到人,导致明明收到了打赏,收益页却一直显示"还没收到任何打赏"。ID 是唯一、不会变的,
// 不存在这个问题,前端个人资料页的"创作者收益"标签页改成调这个接口。
app.get("/api/users/:id/balance", (req, res) => {
  const balanceV2 = db.prepare(
    "SELECT total_pi_units, tip_count, updated_at FROM creator_balances_v2 WHERE creator_user_id = ?"
  ).get(req.params.id);
  if (!balanceV2) return res.json({ total_pi: 0, tip_count: 0, updated_at: null });
  res.json({
    total_pi: balanceV2.total_pi_units / 10000000,
    tip_count: balanceV2.tip_count,
    updated_at: balanceV2.updated_at,
  });
});

// 查询某个创作者的累计打赏收益。优先用 creator_user_id(v2表,真正的记账依据),
// 传的是 username 时先查出对应的 user id 再查,兼容前端仍按用户名展示的场景。
// ⚠️ 保留这个按名字查的旧接口只是为了兼容可能还在用它的旧调用方,新代码一律用
// 上面按 ID 查的 /api/users/:id/balance,不要再依赖这个。
app.get("/api/creators/:name/balance", (req, res) => {
  const { name } = req.params;
  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(name);
  if (user) {
    const balanceV2 = db.prepare(
      "SELECT total_pi_units, tip_count, updated_at FROM creator_balances_v2 WHERE creator_user_id = ?"
    ).get(user.id);
    if (balanceV2) {
      return res.json({
        total_pi: balanceV2.total_pi_units / 10000000,
        tip_count: balanceV2.tip_count,
        updated_at: balanceV2.updated_at,
      });
    }
  }
  // 兜底:v2表里还没有数据(比如迁移前的旧账号),退回旧表按显示名查一次
  const legacy = db.prepare("SELECT total_pi, tip_count, updated_at FROM creator_balances WHERE creator_name = ?").get(name);
  res.json(legacy || { total_pi: 0, tip_count: 0, updated_at: null });
});

/* =========================================================================
   视频上传与Feed接口
   ========================================================================= */
app.post("/api/videos/upload-url", requireAuth, uploadLimiter, async (req, res) => {
  const { filename, contentType } = req.body;
  if (!filename || !contentType) return res.status(400).json({ error: "filename 和 contentType 必填" });
  if (!process.env.R2_BUCKET_NAME || !process.env.R2_ACCOUNT_ID) {
    return res.status(500).json({ error: "服务端未配置 R2 存储,无法生成上传地址,请检查 .env" });
  }

  const videoId = uuidv4();
  const objectKey = `videos/${videoId}-${String(filename).replace(/[^a-zA-Z0-9._-]/g, "_")}`;

  try {
    const command = new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: objectKey, ContentType: contentType });
    const uploadUrl = await getSignedUrl(r2, command, { expiresIn: 600 });
    const publicUrl = `${process.env.R2_PUBLIC_URL}/${objectKey}`;
    res.json({ videoId, uploadUrl, publicUrl });
  } catch (err) {
    console.error("[R2] 生成预签名上传地址失败:", err);
    res.status(500).json({ error: "生成上传地址失败" });
  }
});

app.post("/api/videos", requireAuth, uploadLimiter, (req, res) => {
  const { videoId, caption, videoUrl, thumbnailUrl } = req.body;
  if (!videoId || !videoUrl) return res.status(400).json({ error: "videoId、videoUrl 均为必填" });

  const creator = db.prepare("SELECT id, username FROM users WHERE id = ?").get(req.userId);
  if (!creator) return res.status(401).json({ error: "账号不存在" });

  // 视频审核开关:打开后新视频先进 pending_review,不出现在公开 Feed 里,
  // 需要用 ADMIN_TOKEN 调用 /api/admin/videos/:id/approve 通过后才会公开。
  const status = REQUIRE_VIDEO_REVIEW ? "pending_review" : "published";

  db.prepare(`
    INSERT INTO videos (id, creator_id, creator_name, caption, video_url, thumbnail_url, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(videoId, creator.id, creator.username, caption || "", videoUrl, thumbnailUrl || null, status, Date.now());

  res.json({ ok: true, videoId, status });
});

// Feed流:按发布时间倒序,过滤掉"我拉黑的人"和"拉黑了我的人"发布的内容
app.get("/api/videos/feed", optionalAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 20, 50);
  const before = Number(req.query.before) || Date.now();
  // 本轮新增:?following=1 时只返回"我关注的人"发布的视频,对应首页新增的
  // 左右滑动"关注/推荐"标签页(做法A)。必须登录才有意义,未登录访问直接报错,
  // 前端在没有登录态时会提示登录而不是发这个请求。
  const followingOnly = req.query.following === "1";
  if (followingOnly && !req.userId) {
    return res.status(401).json({ error: "请先登录后查看关注的人发布的视频" });
  }

  // 本轮修复:v.creator_name 只是发布视频那一刻的用户名快照,改资料(改昵称/传头像)
  // 之后永远不会再更新,Feed 卡片一直显示的是最初注册时的旧名字,而且原来这里压根
  // 没有查头像字段——所以头像格子一直是空的。这里改成 LEFT JOIN users 表,取创作者
  // "此刻"真实的昵称和头像(LEFT JOIN 是为了防止创作者账号被删掉后这条视频从 Feed 里
  // 整个消失,这种情况下 creator_display_name/creator_avatar_url 就是 null,前端会自动
  // 回退到旧的 creator_name)。
  let videos;
  if (req.userId && followingOnly) {
    videos = db.prepare(`
      SELECT v.id, v.creator_id, v.creator_name, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
             u.display_name AS creator_display_name, u.avatar_url AS creator_avatar_url,
             (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
      FROM videos v
      LEFT JOIN users u ON u.id = v.creator_id
      WHERE v.status = 'published' AND v.created_at < ?
        AND v.creator_id IN (SELECT creator_id FROM follows WHERE follower_id = ?)
        AND v.creator_id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
        AND v.creator_id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
      ORDER BY v.created_at DESC LIMIT ?
    `).all(before, req.userId, req.userId, req.userId, limit);
  } else if (req.userId) {
    videos = db.prepare(`
      SELECT v.id, v.creator_id, v.creator_name, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
             u.display_name AS creator_display_name, u.avatar_url AS creator_avatar_url,
             (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
      FROM videos v
      LEFT JOIN users u ON u.id = v.creator_id
      WHERE v.status = 'published' AND v.created_at < ?
        AND v.creator_id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
        AND v.creator_id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
      ORDER BY v.created_at DESC LIMIT ?
    `).all(before, req.userId, req.userId, limit);
  } else {
    videos = db.prepare(`
      SELECT v.id, v.creator_id, v.creator_name, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
             u.display_name AS creator_display_name, u.avatar_url AS creator_avatar_url,
             (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
      FROM videos v
      LEFT JOIN users u ON u.id = v.creator_id
      WHERE v.status = 'published' AND v.created_at < ?
      ORDER BY v.created_at DESC LIMIT ?
    `).all(before, limit);
  }

  res.json(videos);
});

// 删除自己发布的视频(本轮新增:此前只能上传,没有删除入口)。
// 只允许作者本人删除,同时清理掉这条视频关联的点赞/评论记录,避免留下指向
// 已删除视频的孤儿数据;R2 上的实际文件也尽量一并删除,但即使 R2 删除失败
// (比如那一刻对象存储抖动)也不影响数据库记录被删除——不能因为清理云存储
// 失败就让用户没法删除自己的作品。
app.delete("/api/videos/:id", requireAuth, async (req, res) => {
  const video = db.prepare("SELECT * FROM videos WHERE id = ?").get(req.params.id);
  if (!video) return res.status(404).json({ error: "视频不存在或已被删除" });
  if (video.creator_id !== req.userId) return res.status(403).json({ error: "只能删除自己发布的作品" });

  const deleteMany = db.transaction(() => {
    db.prepare("DELETE FROM comments WHERE video_id = ?").run(video.id);
    db.prepare("DELETE FROM likes WHERE video_id = ?").run(video.id);
    db.prepare("DELETE FROM videos WHERE id = ?").run(video.id);
  });
  deleteMany();

  const r2PublicUrl = process.env.R2_PUBLIC_URL || "";
  if (r2PublicUrl && video.video_url && video.video_url.startsWith(`${r2PublicUrl}/`)) {
    const objectKey = video.video_url.slice(r2PublicUrl.length + 1);
    try {
      await r2.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: objectKey }));
    } catch (err) {
      console.error("[R2] 删除视频对象失败(数据库记录已删除,不影响本次请求结果):", err.message);
    }
  }

  res.json({ ok: true });
});

// 记一次播放(本轮新增)——之前这个字段从视频发布那一刻起就没被更新过,不管多少人
// 看过都停在初始值 0。这里做的是最基础的版本:前端在一条视频真正开始播放时调用一次,
// 不做"有效观看时长"这类精细统计,只做一个简单的节流:同一个客户端对同一条视频,
// 短时间内重复触发不重复计数(节流逻辑在下面 videoViewThrottle 里,按内存记,重启会清空,
// 足够应付"防止划一下计好几次"这种基本场景,严格防刷后续可以再加)。
const videoViewThrottle = new Map(); // key: `${clientKey}:${videoId}` -> 上次计数的时间戳
const VIEW_THROTTLE_MS = 60 * 1000;
app.post("/api/videos/:id/view", optionalAuth, (req, res) => {
  const videoId = req.params.id;
  const clientKey = req.userId || req.ip || "anon";
  const throttleKey = `${clientKey}:${videoId}`;
  const now = Date.now();
  const last = videoViewThrottle.get(throttleKey);
  if (last && now - last < VIEW_THROTTLE_MS) {
    return res.json({ ok: true, counted: false });
  }
  videoViewThrottle.set(throttleKey, now);
  db.prepare("UPDATE videos SET view_count = view_count + 1 WHERE id = ?").run(videoId);
  res.json({ ok: true, counted: true });
});

app.get("/api/videos/user/:creatorId", (req, res) => {
  // creator_id 本轮补进返回字段:前端"作品"弹层需要靠它判断当前浏览的是不是
  // 自己的作品,来决定要不要显示删除按钮——之前这里没有返回这个字段。
  const videos = db.prepare(`
    SELECT id, creator_id, caption, video_url, thumbnail_url, view_count, like_count, created_at,
           (SELECT COUNT(*) FROM comments WHERE video_id = videos.id) AS comment_count
    FROM videos WHERE creator_id = ? AND status = 'published'
    ORDER BY created_at DESC
  `).all(req.params.creatorId);
  res.json(videos);
});

/* -------------------------------------------------------------------------
   管理员接口(最基础版本):审核 pending_review 状态的视频。
   这不是一个完整的后台管理系统,只是一个用 ADMIN_TOKEN 保护的最小可用接口,
   方便 REQUIRE_VIDEO_REVIEW 打开之后有地方能把视频放出去,交付说明里会
   明确写清楚这一点,建议后续做一个真正的管理后台。
   ------------------------------------------------------------------------- */
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(500).json({ error: "服务端未配置 ADMIN_TOKEN,管理接口不可用" });
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "管理员令牌无效" });
  next();
}
app.get("/api/admin/videos/pending", requireAdmin, (req, res) => {
  const videos = db.prepare("SELECT * FROM videos WHERE status = 'pending_review' ORDER BY created_at ASC").all();
  res.json(videos);
});
app.post("/api/admin/videos/:id/approve", requireAdmin, (req, res) => {
  db.prepare("UPDATE videos SET status = 'published' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});
app.post("/api/admin/videos/:id/reject", requireAdmin, (req, res) => {
  db.prepare("UPDATE videos SET status = 'removed' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

/* =========================================================================
   点赞 / 关注
   ========================================================================= */
app.post("/api/videos/:id/like", requireAuth, (req, res) => {
  const { id: videoId } = req.params;
  const userId = req.userId;

  const video = db.prepare("SELECT id, creator_id, like_count FROM videos WHERE id = ?").get(videoId);
  if (!video) return res.status(404).json({ error: "视频不存在" });

  const existing = db.prepare("SELECT 1 FROM likes WHERE video_id = ? AND user_id = ?").get(videoId, userId);
  const tx = db.transaction(() => {
    if (existing) {
      db.prepare("DELETE FROM likes WHERE video_id = ? AND user_id = ?").run(videoId, userId);
      db.prepare("UPDATE videos SET like_count = MAX(like_count - 1, 0) WHERE id = ?").run(videoId);
    } else {
      db.prepare("INSERT INTO likes (video_id, user_id, created_at) VALUES (?, ?, ?)").run(videoId, userId, Date.now());
      db.prepare("UPDATE videos SET like_count = like_count + 1 WHERE id = ?").run(videoId);
    }
  });
  tx();

  // 点赞(不是取消点赞)时给视频作者发一条通知——本轮新增,之前点赞完全不会留下任何提示。
  if (!existing) {
    createNotification({ userId: video.creator_id, type: "like", actorId: userId, videoId });
  }

  const updated = db.prepare("SELECT like_count FROM videos WHERE id = ?").get(videoId);
  res.json({ liked: !existing, likeCount: updated.like_count });
});

app.get("/api/users/:userId/likes", (req, res) => {
  const rows = db.prepare("SELECT video_id FROM likes WHERE user_id = ?").all(req.params.userId);
  res.json(rows.map((r) => r.video_id));
});

// 本轮新增:我点赞过的作品完整列表(个人资料"喜欢"标签页用)——上面那个 /likes
// 接口只返回一串 video_id,是给 UserSocialState 内部判断"这条我有没有点过赞"用的,
// 不要改动它的返回格式;这个新接口专门给"喜欢"这个标签页用,返回完整视频信息,
// 才能渲染出可以点开连续播放的九宫格(之前"喜欢"标签页其实一直显示的是假的占位数据,
// 点了没反应,根源就是压根没有对接真实接口)。
app.get("/api/users/me/liked-videos", requireAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.creator_id, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
           (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
    FROM likes l
    JOIN videos v ON v.id = l.video_id
    WHERE l.user_id = ? AND v.status = 'published'
    ORDER BY l.created_at DESC
  `).all(req.userId);
  res.json(videos);
});

app.post("/api/users/:id/follow", requireAuth, (req, res) => {
  const creatorId = req.params.id;
  const followerId = req.userId;
  if (followerId === creatorId) return res.status(400).json({ error: "不能关注自己" });

  const existing = db.prepare("SELECT 1 FROM follows WHERE follower_id = ? AND creator_id = ?").get(followerId, creatorId);
  if (existing) {
    db.prepare("DELETE FROM follows WHERE follower_id = ? AND creator_id = ?").run(followerId, creatorId);
  } else {
    db.prepare("INSERT INTO follows (follower_id, creator_id, created_at) VALUES (?, ?, ?)").run(followerId, creatorId, Date.now());
    // 新关注(不是取消关注)时给对方发一条通知——本轮新增。
    createNotification({ userId: creatorId, type: "follow", actorId: followerId });
  }

  const followerCount = db.prepare("SELECT COUNT(*) AS c FROM follows WHERE creator_id = ?").get(creatorId).c;
  res.json({ following: !existing, followerCount });
});

app.get("/api/users/:userId/following", (req, res) => {
  const rows = db.prepare("SELECT creator_id FROM follows WHERE follower_id = ?").all(req.params.userId);
  res.json(rows.map((r) => r.creator_id));
});

// 本轮新增:个人资料页顶部"关注/粉丝/获赞"三个数字之前是写死在页面里的假数据,
// 这里补上真实统计——关注数、粉丝数、获赞数(这个人所有已发布作品的点赞数加总)。
app.get("/api/users/:id/stats", (req, res) => {
  const followingCount = db.prepare("SELECT COUNT(*) AS c FROM follows WHERE follower_id = ?").get(req.params.id).c;
  const followerCount = db.prepare("SELECT COUNT(*) AS c FROM follows WHERE creator_id = ?").get(req.params.id).c;
  const likeCount = db.prepare(
    "SELECT COALESCE(SUM(like_count), 0) AS c FROM videos WHERE creator_id = ? AND status = 'published'"
  ).get(req.params.id).c;
  // 本轮新增:互相关注的人数(A关注了B,B也关注了A),配合前端主页新增的"互关"
  // 入口——之前只有 关注/粉丝/获赞 三个统计,想看"和我互相关注的都有谁"只能
  // 分别翻关注列表和粉丝列表、自己肉眼去对,现在直接给一个数、点进去是筛好的名单。
  const mutualCount = db.prepare(`
    SELECT COUNT(*) AS c FROM follows f1
    WHERE f1.follower_id = ?
      AND EXISTS (SELECT 1 FROM follows f2 WHERE f2.follower_id = f1.creator_id AND f2.creator_id = f1.follower_id)
  `).get(req.params.id).c;
  res.json({ followingCount, followerCount, likeCount, mutualCount });
});

// 本轮新增:互相关注名单——上面 mutualCount 对应的完整列表,给主页新的"互关"
// 入口点开用。复用 followers/following-list 同样的返回结构(id/username/
// displayName/avatarUrl/isMutual),isMutual 这里永远是 true,保留字段只是
// 为了和 FollowListSheet 现成的渲染逻辑保持一致,不用为这一个场景单独写模板。
app.get("/api/users/:id/mutual-follows", (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar_url
    FROM follows f1
    JOIN users u ON u.id = f1.creator_id
    WHERE f1.follower_id = ?
      AND EXISTS (SELECT 1 FROM follows f2 WHERE f2.follower_id = f1.creator_id AND f2.creator_id = f1.follower_id)
    ORDER BY f1.created_at DESC
  `).all(req.params.id);
  res.json(rows.map((r) => ({
    id: r.id, username: r.username, displayName: r.display_name || r.username, avatarUrl: r.avatar_url,
    isMutual: true,
  })));
});

// 本轮新增:粉丝列表(之前只有"我关注了谁"的接口,没有"谁关注了我")。
// is_followed_back 标记这个人是不是也被主页主人关注了——用来在列表里显示"互相关注"标签。
app.get("/api/users/:id/followers", (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar_url,
           EXISTS(SELECT 1 FROM follows WHERE follower_id = ? AND creator_id = u.id) AS is_followed_back
    FROM follows f
    JOIN users u ON u.id = f.follower_id
    WHERE f.creator_id = ?
    ORDER BY f.created_at DESC
  `).all(req.params.id, req.params.id);
  res.json(rows.map((r) => ({
    id: r.id, username: r.username, displayName: r.display_name || r.username, avatarUrl: r.avatar_url,
    isMutual: !!r.is_followed_back,
  })));
});

// 本轮新增:和上面的 /following(只返回 id 数组,是给 UserSocialState 内部用的,
// 不要改动它的返回格式,前端已经依赖它是纯 id 数组了)不同,这个接口返回完整的用户信息,
// 专门给"关注列表"这个新页面用。
app.get("/api/users/:id/following-list", (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar_url,
           EXISTS(SELECT 1 FROM follows WHERE follower_id = u.id AND creator_id = ?) AS is_followed_back
    FROM follows f
    JOIN users u ON u.id = f.creator_id
    WHERE f.follower_id = ?
    ORDER BY f.created_at DESC
  `).all(req.params.id, req.params.id);
  res.json(rows.map((r) => ({
    id: r.id, username: r.username, displayName: r.display_name || r.username, avatarUrl: r.avatar_url,
    isMutual: !!r.is_followed_back,
  })));
});

/* =========================================================================
   收藏(本轮新增)
   ========================================================================= */
// 收藏/取消收藏(切换)。之前"收藏"只存在前端本地缓存里,现在改成和点赞一样
// 落到服务端的 collections 表,换设备登录也能看到,个人资料页也能有一个真实的
// "收藏"标签页。
app.post("/api/videos/:id/collect", requireAuth, (req, res) => {
  const videoId = req.params.id;
  const userId = req.userId;
  const video = db.prepare("SELECT id FROM videos WHERE id = ?").get(videoId);
  if (!video) return res.status(404).json({ error: "视频不存在" });

  const existing = db.prepare("SELECT 1 FROM collections WHERE user_id = ? AND video_id = ?").get(userId, videoId);
  if (existing) {
    db.prepare("DELETE FROM collections WHERE user_id = ? AND video_id = ?").run(userId, videoId);
  } else {
    db.prepare("INSERT INTO collections (user_id, video_id, created_at) VALUES (?, ?, ?)").run(userId, videoId, Date.now());
  }
  res.json({ collected: !existing });
});

// 我收藏过的作品列表(个人资料"收藏"标签页用),只有本人能看自己收藏了什么。
app.get("/api/users/me/collections", requireAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.creator_id, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
           (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
    FROM collections c
    JOIN videos v ON v.id = c.video_id
    WHERE c.user_id = ? AND v.status = 'published'
    ORDER BY c.created_at DESC
  `).all(req.userId);
  res.json(videos);
});

/* =========================================================================
   观看历史(本轮新增)
   ========================================================================= */
// 记一次观看历史,和 /api/videos/:id/view(播放量+1)是两件独立的事:播放量是
// 所有人共享的公开计数,历史浏览是"我自己看过什么"的私人记录,只有登录用户才有。
// 用 INSERT OR REPLACE,同一条视频重复看只更新时间,不会在历史列表里堆出重复行。
app.post("/api/videos/:id/watched", requireAuth, (req, res) => {
  const video = db.prepare("SELECT id FROM videos WHERE id = ?").get(req.params.id);
  if (!video) return res.status(404).json({ error: "视频不存在" });
  db.prepare(`
    INSERT INTO watch_history (user_id, video_id, watched_at) VALUES (?, ?, ?)
    ON CONFLICT(user_id, video_id) DO UPDATE SET watched_at = excluded.watched_at
  `).run(req.userId, req.params.id, Date.now());
  res.json({ ok: true });
});

// 历史浏览列表(个人资料"历史浏览"标签页用),最近看过的排在最前面,只保留最近 200 条。
app.get("/api/users/me/history", requireAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.creator_id, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
           h.watched_at,
           (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
    FROM watch_history h
    JOIN videos v ON v.id = h.video_id
    WHERE h.user_id = ? AND v.status = 'published'
    ORDER BY h.watched_at DESC
    LIMIT 200
  `).all(req.userId);
  res.json(videos);
});

/* =========================================================================
   通知(本轮新增)——赞/评论/关注/打赏 + 平台系统公告
   ========================================================================= */
// 我的通知列表,关联发起人的"此刻"真实昵称/头像(和评论、Feed 头像同样的思路),
// 以及(如果有关联视频)视频的封面,方便点开通知直接跳转。
app.get("/api/notifications", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT n.id, n.type, n.actor_id, n.video_id, n.content, n.created_at, n.read_at,
           u.username AS actor_username, u.display_name AS actor_display_name, u.avatar_url AS actor_avatar_url,
           v.thumbnail_url AS video_thumbnail_url
    FROM notifications n
    LEFT JOIN users u ON u.id = n.actor_id
    LEFT JOIN videos v ON v.id = n.video_id
    WHERE n.user_id = ?
    ORDER BY n.created_at DESC
    LIMIT 100
  `).all(req.userId);
  res.json(rows.map((r) => ({
    id: r.id, type: r.type, videoId: r.video_id, content: r.content,
    createdAt: r.created_at, read: !!r.read_at,
    actor: r.actor_id ? {
      id: r.actor_id, username: r.actor_username,
      displayName: r.actor_display_name || r.actor_username,
      avatarUrl: r.actor_avatar_url,
    } : null,
    videoThumbnailUrl: r.video_thumbnail_url || null,
  })));
});

app.get("/api/notifications/unread-count", requireAuth, (req, res) => {
  const row = db.prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read_at IS NULL").get(req.userId);
  res.json({ unreadCount: row.c });
});

app.post("/api/notifications/mark-read", requireAuth, (req, res) => {
  db.prepare("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL").run(Date.now(), req.userId);
  res.json({ ok: true });
});

// 平台系统公告(本轮新增最基础版本):用 ADMIN_TOKEN 保护,给所有用户群发一条
// type='system' 的通知。这是"平台和用户之间的推送沟通渠道"最小可用的起点,
// 还没有可视化的后台界面,发公告目前需要用 ADMIN_TOKEN 手动调用这个接口。
app.post("/api/admin/notifications/broadcast", requireAdmin, (req, res) => {
  const { content } = req.body;
  if (!content || !String(content).trim()) return res.status(400).json({ error: "content 必填" });
  const users = db.prepare("SELECT id FROM users").all();
  const now = Date.now();
  const insertMany = db.transaction((rows) => {
    const stmt = db.prepare(`
      INSERT INTO notifications (id, user_id, type, actor_id, video_id, content, created_at)
      VALUES (?, ?, 'system', NULL, NULL, ?, ?)
    `);
    for (const u of rows) stmt.run(uuidv4(), u.id, String(content).trim().slice(0, 500), now);
  });
  insertMany(users);
  res.json({ ok: true, recipientCount: users.length });
});

/* =========================================================================
   评论
   ========================================================================= */
// 本轮修复:评论列表关联用户表,取"此刻"真实的昵称和头像(不再是发评论那一刻的
// 用户名快照),前端才能显示和个人资料一致的头像/昵称,并支持点击跳转到对方主页。
app.get("/api/videos/:id/comments", (req, res) => {
  const comments = db.prepare(`
    SELECT c.id, c.user_id, c.username, c.content, c.created_at,
           u.display_name AS display_name, u.avatar_url AS avatar_url
    FROM comments c
    LEFT JOIN users u ON u.id = c.user_id
    WHERE c.video_id = ?
    ORDER BY c.created_at ASC
  `).all(req.params.id);
  res.json(comments.map((c) => ({
    id: c.id, userId: c.user_id, username: c.username,
    displayName: c.display_name || c.username,
    avatarUrl: c.avatar_url || null,
    content: c.content, created_at: c.created_at,
  })));
});

app.post("/api/videos/:id/comments", requireAuth, commentLimiter, (req, res) => {
  const { content } = req.body;
  if (!content || !String(content).trim()) return res.status(400).json({ error: "content 必填" });

  const video = db.prepare("SELECT id, creator_id FROM videos WHERE id = ?").get(req.params.id);
  if (!video) return res.status(404).json({ error: "视频不存在" });

  const user = db.prepare("SELECT id, username, display_name, avatar_url FROM users WHERE id = ?").get(req.userId);
  if (!user) return res.status(401).json({ error: "账号不存在" });

  const comment = {
    id: uuidv4(), video_id: req.params.id, user_id: user.id, username: user.username,
    content: String(content).trim().slice(0, 500), created_at: Date.now(),
  };
  db.prepare(`
    INSERT INTO comments (id, video_id, user_id, username, content, created_at)
    VALUES (@id, @video_id, @user_id, @username, @content, @created_at)
  `).run(comment);

  // 给视频作者发一条"有人评论了你的作品"通知(本轮新增),附带评论内容摘要方便一眼看懂。
  createNotification({
    userId: video.creator_id, type: "comment", actorId: user.id, videoId: video.id,
    content: comment.content.slice(0, 60),
  });

  res.json({
    id: comment.id, userId: comment.user_id, username: comment.username,
    displayName: user.display_name || user.username,
    avatarUrl: user.avatar_url || null,
    content: comment.content, created_at: comment.created_at,
  });
});

/* =========================================================================
   个人资料
   ========================================================================= */
// 查看任意用户的公开资料(本轮新增)——之前完全没有"按 id 查询他人资料"的接口,
// 只有修改"自己"资料的 PATCH。导致点开别人主页时("访客模式"),前端连问都没地方问,
// 只能一直显示占位头像和 Feed 卡片里可能已经过期的旧昵称,改了资料对方也看不到更新。
// 不要求登录(和查看别人的公开作品一样,谁都能看),只返回公开字段。
// 本轮新增 optionalAuth:如果请求带了登录态,顺便算出"这个被访问的人是不是也关注了我"
// (followsMe),配合前端在对方主页的关注按钮上显示"互相关注"状态——之前这个接口
// 完全不管请求者是谁,前端拿不到这个信息,关注按钮永远只有"关注"/"已关注"两种状态。
app.get("/api/users/:id", optionalAuth, (req, res) => {
  const user = db.prepare("SELECT id, username, display_name, avatar_url, background_url, age_tier, bio FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });
  const view = publicUserView(user);
  if (req.userId && req.userId !== user.id) {
    const followsMe = !!db.prepare("SELECT 1 FROM follows WHERE follower_id = ? AND creator_id = ?").get(user.id, req.userId);
    view.followsMe = followsMe;
  }
  res.json(view);
});

app.patch("/api/users/:id", requireAuth, (req, res) => {
  if (req.params.id !== req.userId) return res.status(403).json({ error: "只能修改自己的资料" });
  // 本轮新增 avatarUrl/backgroundUrl:两者都只接受本站 R2 公开域名下的地址
  // (见下面 /api/users/me/image-upload-url),不接受任意外部 URL,避免被用来
  // 拼接一个跳转到钓鱼页面/加载不可控内容的链接。
  const { displayName, bio, avatarUrl, backgroundUrl } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });

  const nextDisplayName = (displayName || "").trim().slice(0, 40) || user.display_name;
  const nextBio = (bio || "").trim().slice(0, 200);
  const r2PublicUrl = process.env.R2_PUBLIC_URL || "";
  const isValidR2Url = (url) => typeof url === "string" && r2PublicUrl && url.startsWith(`${r2PublicUrl}/`);
  const nextAvatarUrl = avatarUrl !== undefined
    ? (isValidR2Url(avatarUrl) ? avatarUrl : user.avatar_url)
    : user.avatar_url;
  const nextBackgroundUrl = backgroundUrl !== undefined
    ? (isValidR2Url(backgroundUrl) ? backgroundUrl : user.background_url)
    : user.background_url;

  db.prepare("UPDATE users SET display_name = ?, bio = ?, avatar_url = ?, background_url = ? WHERE id = ?")
    .run(nextDisplayName, nextBio, nextAvatarUrl, nextBackgroundUrl, req.params.id);
  const updated = db.prepare("SELECT id, username, display_name, avatar_url, background_url, bio FROM users WHERE id = ?").get(req.params.id);
  res.json(publicUserView(updated));
});

// 头像 / 个人资料背景图 / 视频封面图上传:都是同一套"预签名直传 R2"模式,
// 只是换了存储路径前缀和校验(必须是 image/*)。
// 本轮新增 "thumbnail" 这个 kind——配合前端发布视频时新增的"客户端截帧生成封面"
// 逻辑,解决作品栏/首页视频没有封面、只能看到纯色空框的问题。
app.post("/api/users/me/image-upload-url", requireAuth, uploadLimiter, async (req, res) => {
  const { kind, filename, contentType } = req.body;
  if (!["avatar", "background", "thumbnail"].includes(kind)) {
    return res.status(400).json({ error: "kind 必须是 avatar、background 或 thumbnail" });
  }
  if (!filename || !contentType) return res.status(400).json({ error: "filename 和 contentType 必填" });
  if (!String(contentType).startsWith("image/")) return res.status(400).json({ error: "只能上传图片文件" });
  if (!process.env.R2_BUCKET_NAME || !process.env.R2_ACCOUNT_ID) {
    return res.status(500).json({ error: "服务端未配置 R2 存储,无法生成上传地址,请检查 .env" });
  }

  const prefix = kind === "avatar" ? "avatars" : kind === "background" ? "backgrounds" : "thumbnails";
  const objectKey = `${prefix}/${req.userId}-${Date.now()}-${String(filename).replace(/[^a-zA-Z0-9._-]/g, "_")}`;

  try {
    const command = new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: objectKey, ContentType: contentType });
    const uploadUrl = await getSignedUrl(r2, command, { expiresIn: 600 });
    const publicUrl = `${process.env.R2_PUBLIC_URL}/${objectKey}`;
    res.json({ uploadUrl, publicUrl });
  } catch (err) {
    console.error("[R2] 生成头像/背景图预签名上传地址失败:", err);
    res.status(500).json({ error: "生成上传地址失败" });
  }
});

/* =========================================================================
   举报 / 拉黑(本轮新增,最基础版本)
   ========================================================================= */
app.post("/api/reports", requireAuth, (req, res) => {
  const { targetType, targetId, reason } = req.body;
  if (!["video", "comment", "user", "message"].includes(targetType) || !targetId) {
    return res.status(400).json({ error: "targetType 需为 video/comment/user/message 之一,targetId 必填" });
  }
  db.prepare(`
    INSERT INTO reports (id, reporter_id, target_type, target_id, reason, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(uuidv4(), req.userId, targetType, String(targetId), (reason || "").slice(0, 500), Date.now());
  res.json({ ok: true });
});

app.post("/api/users/:id/block", requireAuth, (req, res) => {
  const blockedId = req.params.id;
  if (blockedId === req.userId) return res.status(400).json({ error: "不能拉黑自己" });
  db.prepare("INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)")
    .run(req.userId, blockedId, Date.now());
  res.json({ ok: true });
});
app.delete("/api/users/:id/block", requireAuth, (req, res) => {
  db.prepare("DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?").run(req.userId, req.params.id);
  res.json({ ok: true });
});
app.get("/api/users/me/blocked", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT blocked_id FROM blocks WHERE blocker_id = ?").all(req.userId);
  res.json(rows.map((r) => r.blocked_id));
});

/* =========================================================================
   会话(私信/群聊)
   ========================================================================= */
// 本轮修复:之前这个接口对一对一私信(type='direct')完全没有返回对方的用户名/头像
// ——c.group_name/c.group_avatar_url 只有群聊会有值,一对一私信这两个字段永远是 NULL,
// 导致前端会话列表只能显示兜底文案"对话"和一个空的头像圆圈,用户完全看不出这条
// 私信是跟谁聊的。这里补一个 LEFT JOIN 找出"这个会话里除了我之外的另一个成员",
// 把TA的用户名/昵称/头像也一起查出来,直接在 direct 类型的会话上用它兜底。
app.get("/api/conversations", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.type, c.group_name, c.group_avatar_url,
      (SELECT content FROM messages WHERE conversation_id = c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_message_at,
      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.created_at > cm.last_read_at) AS unread_count,
      ou.id AS other_user_id, ou.username AS other_username, ou.display_name AS other_display_name, ou.avatar_url AS other_avatar_url
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id
    LEFT JOIN conversation_members ocm ON ocm.conversation_id = c.id AND ocm.user_id != ?
    LEFT JOIN users ou ON ou.id = ocm.user_id AND c.type = 'direct'
    WHERE cm.user_id = ?
    ORDER BY last_message_at DESC
  `).all(req.userId, req.userId);
  res.json(rows.map((r) => ({
    id: r.id,
    type: r.type,
    name: r.type === "direct" ? (r.other_display_name || r.other_username || null) : r.group_name,
    avatarUrl: r.type === "direct" ? r.other_avatar_url : r.group_avatar_url,
    otherUserId: r.type === "direct" ? r.other_user_id : null,
    last_message: r.last_message,
    last_message_at: r.last_message_at,
    unread_count: r.unread_count,
  })));
});

// 本轮新增:私信入口的小红点角标要用——把这个人所有会话里的未读消息数加起来,
// 不用像 /api/conversations 那样把整个会话列表(含最后一条消息内容)都传回来,
// 首页每次要刷新角标时用这个轻量接口就够了。
app.get("/api/conversations/unread-count", requireAuth, (req, res) => {
  const row = db.prepare(`
    SELECT COALESCE(SUM(
      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = cm.conversation_id AND m.created_at > cm.last_read_at)
    ), 0) AS total
    FROM conversation_members cm
    WHERE cm.user_id = ?
  `).get(req.userId);
  res.json({ unreadCount: row.total });
});

app.post("/api/conversations/direct", requireAuth, (req, res) => {
  const { targetUserId } = req.body;
  if (!targetUserId) return res.status(400).json({ error: "targetUserId 必填" });

  // 拉黑检查:双方任意一方拉黑了对方,都不能新建私信会话
  const blocked = db.prepare(`
    SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
  `).get(req.userId, targetUserId, targetUserId, req.userId);
  if (blocked) return res.status(403).json({ error: "无法与该用户建立会话" });

  // 年龄分级限制:未成年账号只能被自己已关注的人私信
  const target = db.prepare("SELECT age_tier FROM users WHERE id = ?").get(targetUserId);
  if (target && !canDMFromStrangers(target.age_tier)) {
    const isFollowed = db.prepare("SELECT 1 FROM follows WHERE follower_id = ? AND creator_id = ?").get(targetUserId, req.userId);
    if (!isFollowed) return res.status(403).json({ error: "对方账号年龄分级限制,暂不能接收陌生人私信" });
  }

  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = ?
    JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = ?
    WHERE c.type = 'direct'
  `).get(req.userId, targetUserId);
  if (existing) return res.json({ id: existing.id, existed: true });

  const conversationId = uuidv4();
  const now = Date.now();
  const insertConv = db.prepare("INSERT INTO conversations (id, type, created_by, created_at) VALUES (?, 'direct', ?, ?)");
  const insertMember = db.prepare("INSERT INTO conversation_members (conversation_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)");
  const tx = db.transaction(() => {
    insertConv.run(conversationId, req.userId, now);
    insertMember.run(conversationId, req.userId, now);
    insertMember.run(conversationId, targetUserId, now);
  });
  tx();
  res.json({ id: conversationId, existed: false });
});

app.post("/api/conversations/group", requireAuth, (req, res) => {
  const { groupName, memberIds } = req.body;
  if (!groupName || !Array.isArray(memberIds) || memberIds.length === 0) {
    return res.status(400).json({ error: "groupName 和 memberIds(数组) 必填" });
  }
  const conversationId = uuidv4();
  const now = Date.now();
  const insertConv = db.prepare("INSERT INTO conversations (id, type, group_name, created_by, created_at) VALUES (?, 'group', ?, ?, ?)");
  const insertMember = db.prepare("INSERT INTO conversation_members (conversation_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)");
  const tx = db.transaction(() => {
    insertConv.run(conversationId, groupName, req.userId, now);
    insertMember.run(conversationId, req.userId, "owner", now);
    memberIds.forEach((uid) => { if (uid !== req.userId) insertMember.run(conversationId, uid, "member", now); });
  });
  tx();
  res.json({ id: conversationId });
});

app.get("/api/conversations/:id/messages", requireAuth, (req, res) => {
  const { id } = req.params;
  const before = Number(req.query.before) || Date.now();
  const limit = Math.min(Number(req.query.limit) || 30, 100);

  const member = db.prepare("SELECT cleared_before FROM conversation_members WHERE conversation_id = ? AND user_id = ?").get(id, req.userId);
  if (!member) return res.status(403).json({ error: "你不是该会话成员" });

  // 本轮修复:之前这里 SELECT * 会把撤回/删除的消息(deleted_at 不为空)也一起
  // 返回,前端并没有处理这种情况,结果撤回后的消息内容原样还在界面上,等于
  // "删除"完全没生效。现在过滤掉已删除的,同时用 cleared_before 支持
  // "清空聊天记录"——清空只影响我自己这一侧看到的历史,不影响对方。
  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE conversation_id = ? AND created_at < ? AND created_at > ? AND deleted_at IS NULL
    ORDER BY created_at DESC LIMIT ?
  `).all(id, before, member.cleared_before || 0, limit);
  res.json(messages.reverse());
});

app.post("/api/conversations/:id/read", requireAuth, (req, res) => {
  db.prepare("UPDATE conversation_members SET last_read_at = ? WHERE conversation_id = ? AND user_id = ?")
    .run(Date.now(), req.params.id, req.userId);
  res.json({ ok: true });
});

// 本轮新增:删除单条消息(撤回)。只允许发送者本人删除,软删除(deleted_at)
// 不物理删掉记录,方便日后申诉/审计;删除后消息就不会再出现在
// GET /api/conversations/:id/messages 的结果里。
app.delete("/api/conversations/:id/messages/:messageId", requireAuth, (req, res) => {
  const { id, messageId } = req.params;
  const isMember = db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?").get(id, req.userId);
  if (!isMember) return res.status(403).json({ error: "你不是该会话成员" });
  const message = db.prepare("SELECT id, sender_id FROM messages WHERE id = ? AND conversation_id = ?").get(messageId, id);
  if (!message) return res.status(404).json({ error: "消息不存在" });
  if (message.sender_id !== req.userId) return res.status(403).json({ error: "只能删除自己发送的消息" });
  db.prepare("UPDATE messages SET deleted_at = ? WHERE id = ?").run(Date.now(), messageId);
  io.to(`user:${req.userId}`).emit("message_deleted", { conversationId: id, messageId });
  // 通知对方那一侧也把这条消息去掉,避免出现"我这边删了、对方那边还在"的不一致
  const otherMembers = db.prepare("SELECT user_id FROM conversation_members WHERE conversation_id = ? AND user_id != ?").all(id, req.userId);
  otherMembers.forEach((m) => io.to(`user:${m.user_id}`).emit("message_deleted", { conversationId: id, messageId }));
  res.json({ ok: true });
});

// 本轮新增:清空聊天记录。只清空"我"这一侧从现在往前看到的历史(把
// cleared_before 设成当前时间),不删除消息本身、不影响对方看到的记录——
// 和主流 IM 产品"清空聊天记录只清自己这边"的行为一致。
app.post("/api/conversations/:id/clear", requireAuth, (req, res) => {
  const isMember = db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?").get(req.params.id, req.userId);
  if (!isMember) return res.status(403).json({ error: "你不是该会话成员" });
  db.prepare("UPDATE conversation_members SET cleared_before = ?, last_read_at = ? WHERE conversation_id = ? AND user_id = ?")
    .run(Date.now(), Date.now(), req.params.id, req.userId);
  res.json({ ok: true });
});

/* =========================================================================
   直播功能(本轮新增,对应"直播功能_技术方案与开发计划"文档的 Phase 0+1+2):
   主播开播/结束、直播广场列表、观众加入。音视频推拉流走 LiveKit(第三方
   RTC云服务),这里的接口只负责"发一个有权限的房间令牌"和"记录一场直播的
   生命周期",真正的音视频数据不经过我们自己的服务器。
   聊天/点赞飘心复用下面 Socket.io 里的 `live:${livestreamId}` 房间,不在这里。
   礼物系统、禁言/踢人、未成年人限制等还没做(见开发计划里 Phase 4/5),
   现在这一批先把"能开播、能看、能聊天、能点赞飘心"这个最小闭环跑通,
   重点是在 Pi Browser 里实测这条链路到底通不通、体验怎么样。
   ========================================================================= */
function requireLiveKitConfigured(req, res, next) {
  if (!LIVEKIT_URL || !LIVEKIT_API_KEY || !LIVEKIT_API_SECRET) {
    return res.status(503).json({ error: "直播服务尚未配置(缺少 LIVEKIT_URL / LIVEKIT_API_KEY / LIVEKIT_API_SECRET),请先在 .env 里填好" });
  }
  next();
}

// 主播开播:创建一条直播记录,签发一个"可以推流"的 LiveKit token
app.post("/api/livestreams/start", requireAuth, requireLiveKitConfigured, async (req, res) => {
  try {
    // 同一个账号不允许同时开两场直播——如果有一场还挂在 live 状态,直接把它的信息返回,
    // 而不是报错,这样"忘了结束、直接刷新页面重新点开播"的常见情况能自动接回上一场。
    const existing = db.prepare(
      "SELECT id, room_name, title, started_at FROM livestreams WHERE host_id = ? AND status = 'live'"
    ).get(req.userId);
    const user = db.prepare("SELECT id, username, display_name, avatar_url FROM users WHERE id = ?").get(req.userId);
    if (!user) return res.status(404).json({ error: "账号不存在" });

    if (existing) {
      const token = await buildLiveKitToken(req.userId, user.display_name || user.username, existing.room_name, { canPublish: true });
      return res.json({
        livestream: {
          id: existing.id, roomName: existing.room_name, title: existing.title, status: "live", startedAt: existing.started_at,
          host: { id: user.id, username: user.username, displayName: user.display_name, avatarUrl: user.avatar_url },
        },
        wsUrl: LIVEKIT_URL,
        token,
        resumed: true,
      });
    }

    const title = typeof req.body?.title === "string" ? req.body.title.trim().slice(0, 100) : "";
    const id = uuidv4();
    const roomName = `live_${id}`;
    const now = Date.now();
    db.prepare(`
      INSERT INTO livestreams (id, host_id, room_name, provider, title, status, peak_viewer_count, started_at)
      VALUES (?, ?, ?, 'livekit', ?, 'live', 0, ?)
    `).run(id, req.userId, roomName, title || null, now);

    const token = await buildLiveKitToken(req.userId, user.display_name || user.username, roomName, { canPublish: true });
    res.json({
      livestream: {
        id, roomName, title: title || null, status: "live", startedAt: now,
        host: { id: user.id, username: user.username, displayName: user.display_name, avatarUrl: user.avatar_url },
      },
      wsUrl: LIVEKIT_URL,
      token,
      resumed: false,
    });
  } catch (err) {
    console.error("[POST /api/livestreams/start] 出错:", err);
    res.status(500).json({ error: "开播失败,请稍后重试" });
  }
});

// 主播结束直播(幂等:重复调用不报错)
app.post("/api/livestreams/:id/end", requireAuth, (req, res) => {
  const live = db.prepare("SELECT id, host_id, status FROM livestreams WHERE id = ?").get(req.params.id);
  if (!live) return res.status(404).json({ error: "直播不存在" });
  if (live.host_id !== req.userId) return res.status(403).json({ error: "只有主播本人能结束这场直播" });
  if (live.status !== "ended") {
    db.prepare("UPDATE livestreams SET status = 'ended', ended_at = ? WHERE id = ?").run(Date.now(), req.params.id);
  }
  io.to(`live:${req.params.id}`).emit("live_ended", { livestreamId: req.params.id });
  res.json({ ok: true });
});

// 直播广场:当前正在直播的列表(在线人数是现场从 Socket.io 房间人数里读的,不是查表)
app.get("/api/livestreams/live", optionalAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT l.id, l.title, l.started_at,
           u.id AS host_id, u.username AS host_username, u.display_name AS host_display_name, u.avatar_url AS host_avatar_url
    FROM livestreams l
    JOIN users u ON u.id = l.host_id
    WHERE l.status = 'live'
    ORDER BY l.started_at DESC
    LIMIT 50
  `).all();
  const list = rows.map((r) => ({
    id: r.id,
    title: r.title,
    startedAt: r.started_at,
    viewerCount: io.sockets.adapter.rooms.get(`live:${r.id}`)?.size || 0,
    host: { id: r.host_id, username: r.host_username, displayName: r.host_display_name, avatarUrl: r.host_avatar_url },
  }));
  res.json({ livestreams: list });
});

// 观众加入直播间:签发一个"只能拉流看、不能推流"的 LiveKit token。
// 如果是主播本人调用这个接口(比如主播端页面刷新了),照样给推流权限。
app.post("/api/livestreams/:id/join", requireAuth, requireLiveKitConfigured, async (req, res) => {
  try {
    const live = db.prepare(`
      SELECT l.id, l.room_name, l.status, l.title, l.started_at,
             u.id AS host_id, u.username AS host_username, u.display_name AS host_display_name, u.avatar_url AS host_avatar_url
      FROM livestreams l JOIN users u ON u.id = l.host_id
      WHERE l.id = ?
    `).get(req.params.id);
    if (!live) return res.status(404).json({ error: "直播不存在" });
    if (live.status !== "live") return res.status(410).json({ error: "这场直播已经结束了" });

    const viewer = db.prepare("SELECT id, username, display_name FROM users WHERE id = ?").get(req.userId);
    if (!viewer) return res.status(404).json({ error: "账号不存在" });
    const canPublish = live.host_id === req.userId;
    const token = await buildLiveKitToken(req.userId, viewer.display_name || viewer.username, live.room_name, { canPublish });

    res.json({
      livestream: {
        id: live.id, roomName: live.room_name, title: live.title, startedAt: live.started_at,
        host: { id: live.host_id, username: live.host_username, displayName: live.host_display_name, avatarUrl: live.host_avatar_url },
      },
      wsUrl: LIVEKIT_URL,
      token,
      isHost: canPublish,
    });
  } catch (err) {
    console.error("[POST /api/livestreams/:id/join] 出错:", err);
    res.status(500).json({ error: "加入直播间失败,请稍后重试" });
  }
});

/* =========================================================================
   金币钱包 + 礼物系统(本轮新增,对应你确认的"方案甲":用户先用真实 Pi
   买平台金币——固定汇率 1 Pi = 10 金币,走的是和上面 /api/payments/approve、
   /api/payments/complete 完全一样的两段式 Pi 支付流程,只是最后落账的地方
   从 tips 表换成 wallets.coin_balance——送礼物时直接从金币余额里瞬间扣除,
   不再单独发起一笔链上交易。主播收到礼物,累积到自己的"钻石余额"
   (diamond_balance),钻石提现成 Pi 这件事本轮明确不做,只留字段占位。
   ========================================================================= */
const COIN_PER_PI = 10; // 固定汇率:1 Pi = 10 平台金币

// 取(或懒创建)一个账号的钱包行。绝大多数账号在注册时不会立刻有钱包记录,
// 第一次查询/消费/充值时才需要它存在,所以用 INSERT OR IGNORE 保证幂等。
function getOrCreateWallet(userId) {
  db.prepare(`INSERT OR IGNORE INTO wallets (user_id, coin_balance, diamond_balance, updated_at) VALUES (?, 0, 0, ?)`)
    .run(userId, Date.now());
  return db.prepare("SELECT user_id, coin_balance, diamond_balance FROM wallets WHERE user_id = ?").get(userId);
}

// 查询我自己的钱包余额
app.get("/api/wallet/me", requireAuth, (req, res) => {
  const wallet = getOrCreateWallet(req.userId);
  res.json({ coinBalance: wallet.coin_balance, diamondBalance: wallet.diamond_balance });
});

// 充值第一步:批准 Pi 支付(结构照抄 /api/payments/approve,只是落账目标表换成
// coin_purchases 而不是 tips)。coin_amount 按下单那一刻的固定汇率算好存起来,
// 即使汇率以后调整也不影响这笔已经发起的订单。
app.post("/api/wallet/purchase/approve", requireAuth, paymentLimiter, async (req, res) => {
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: "paymentId 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Wallet] ⚠️ PI_API_KEY 未配置,无法调用 Pi 官方 API,批准请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/approve`, {
      method: "POST",
      headers: { Authorization: `Key ${process.env.PI_API_KEY}` },
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 批准金币充值支付失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 批准失败", detail: errText });
    }
    const payment = await response.json();

    try {
      const piAmountUnits = Math.round(Number(payment.amount) * 10000000);
      const coinAmount = Math.round(Number(payment.amount) * COIN_PER_PI);
      db.prepare(`
        INSERT OR IGNORE INTO coin_purchases
          (id, payment_id, buyer_user_id, pi_amount, pi_amount_units, coin_amount, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'approved', ?)
      `).run(uuidv4(), paymentId, req.userId, payment.amount, piAmountUnits, coinAmount, Date.now());
    } catch (dbErr) {
      console.error("[Wallet] ⚠️ 写入金币充值流水表失败(不影响本次支付批准结果):", dbErr);
    }

    res.json({ ok: true, payment });
  } catch (err) {
    console.error("[Pi API] 批准金币充值支付出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

// 充值第二步:确认支付完成、真正把金币加到钱包里(结构照抄 /api/payments/complete
// 的幂等写法:原子的 "UPDATE ... WHERE status='approved'" + .changes 判断,
// Pi SDK 自动重试或用户手动重复点击都不会导致同一笔充值被重复加两次金币)。
app.post("/api/wallet/purchase/complete", requireAuth, paymentLimiter, async (req, res) => {
  const { paymentId, txid } = req.body;
  if (!paymentId || !txid) return res.status(400).json({ error: "paymentId 和 txid 必填" });
  if (!process.env.PI_API_KEY) {
    console.error("[Wallet] ⚠️ PI_API_KEY 未配置,无法调用 Pi 官方 API,完成请求已中止");
    return res.status(500).json({ error: "服务端未配置 PI_API_KEY,无法调用 Pi 官方 API" });
  }

  try {
    const response = await fetch(`${PI_API_BASE}/payments/${paymentId}/complete`, {
      method: "POST",
      headers: { Authorization: `Key ${process.env.PI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ txid }),
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error("[Pi API] 完成金币充值确认失败:", response.status, errText);
      return res.status(502).json({ ok: false, error: "Pi 官方 API 完成确认失败", detail: errText });
    }
    const payment = await response.json();

    let newCoinBalance = null;
    try {
      const tx = db.transaction(() => {
        const updateResult = db.prepare(
          "UPDATE coin_purchases SET status = 'completed', tx_id = ?, completed_at = ? WHERE payment_id = ? AND status = 'approved'"
        ).run(txid, Date.now(), paymentId);

        if (updateResult.changes !== 1) {
          console.warn(`[Wallet] paymentId=${paymentId} 不是首次 complete(可能是重试),跳过金币入账,这是预期行为`);
          return;
        }

        const purchase = db.prepare("SELECT coin_amount, buyer_user_id FROM coin_purchases WHERE payment_id = ?").get(paymentId);
        if (!purchase) return;

        getOrCreateWallet(purchase.buyer_user_id); // 确保钱包行已存在
        db.prepare(`UPDATE wallets SET coin_balance = coin_balance + ?, updated_at = ? WHERE user_id = ?`)
          .run(purchase.coin_amount, Date.now(), purchase.buyer_user_id);

        newCoinBalance = db.prepare("SELECT coin_balance FROM wallets WHERE user_id = ?").get(purchase.buyer_user_id)?.coin_balance;
      });
      tx();
    } catch (dbErr) {
      console.error("[Wallet] ⚠️ 更新金币充值流水/钱包余额失败(不影响本次支付完成结果):", dbErr);
    }

    res.json({ ok: true, payment, coinBalance: newCoinBalance });
  } catch (err) {
    console.error("[Pi API] 完成金币充值确认出错:", err);
    res.status(500).json({ ok: false, error: "服务端调用 Pi API 出错" });
  }
});

// 礼物目录:公开可查(不需要登录也能看直播间礼物墙长什么样)
app.get("/api/gifts/catalog", optionalAuth, (req, res) => {
  const gifts = db.prepare(`
    SELECT id, name, icon, coin_price AS coinPrice, tier, sort_order AS sortOrder
    FROM gift_catalog WHERE is_active = 1 ORDER BY sort_order ASC
  `).all();
  res.json({ gifts });
});

// 送礼物:直播间里送给主播。原子扣减发送者金币余额 + 累加主播钻石余额,
// 余额不够直接拒绝(不允许透支),成功后广播 live_gift 事件驱动前端动效
// 和聊天区横幅,并给主播发一条通知(复用 notifications.type='tip',因为
// notifications 表的 CHECK 约束目前只允许 like/comment/follow/tip/system 这几种,
// 给已经在生产环境跑着的旧数据库加新枚举值需要重建整张表、风险较高,这里选择
// 用 content 文案区分"这是一条礼物通知"而不是改表结构)。
app.post("/api/livestreams/:id/gifts", requireAuth, paymentLimiter, (req, res) => {
  const livestreamId = req.params.id;
  const giftId = String(req.body?.giftId || "");
  const quantity = Math.max(1, Math.min(99, parseInt(req.body?.quantity, 10) || 1));
  if (!giftId) return res.status(400).json({ error: "giftId 必填" });

  const live = db.prepare("SELECT id, host_id, status FROM livestreams WHERE id = ?").get(livestreamId);
  if (!live) return res.status(404).json({ error: "直播不存在" });
  if (live.status !== "live") return res.status(410).json({ error: "这场直播已经结束了" });
  if (live.host_id === req.userId) return res.status(400).json({ error: "不能给自己送礼物" });

  const gift = db.prepare("SELECT id, name, icon, coin_price FROM gift_catalog WHERE id = ? AND is_active = 1").get(giftId);
  if (!gift) return res.status(404).json({ error: "礼物不存在或已下架" });

  const senderTierRow = db.prepare("SELECT age_tier FROM users WHERE id = ?").get(req.userId);
  if (senderTierRow && !canTip(senderTierRow.age_tier)) return res.status(403).json({ error: "当前账号年龄分级不允许送礼物" });
  const host = db.prepare("SELECT age_tier, username, display_name FROM users WHERE id = ?").get(live.host_id);
  if (host && !canReceiveTip(host.age_tier)) return res.status(403).json({ error: "对方账号年龄分级不允许接收礼物" });

  const coinCost = gift.coin_price * quantity;
  let result;
  try {
    const tx = db.transaction(() => {
      getOrCreateWallet(req.userId);
      getOrCreateWallet(live.host_id);

      // 原子扣费:UPDATE ... WHERE coin_balance >= ? ,一步到位判断余额是否够、
      // 不够就不会真的扣掉——避免"先查余额、再扣款"两步之间的并发竞态窗口。
      const deduct = db.prepare(
        "UPDATE wallets SET coin_balance = coin_balance - ?, updated_at = ? WHERE user_id = ? AND coin_balance >= ?"
      ).run(coinCost, Date.now(), req.userId, coinCost);
      if (deduct.changes !== 1) {
        result = { insufficient: true };
        return;
      }

      db.prepare("UPDATE wallets SET diamond_balance = diamond_balance + ?, updated_at = ? WHERE user_id = ?")
        .run(coinCost, Date.now(), live.host_id);

      const sendId = uuidv4();
      const now = Date.now();
      db.prepare(`
        INSERT INTO gift_sends (id, livestream_id, gift_id, sender_id, receiver_id, quantity, coin_cost, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(sendId, livestreamId, gift.id, req.userId, live.host_id, quantity, coinCost, now);

      const senderCoinBalance = db.prepare("SELECT coin_balance FROM wallets WHERE user_id = ?").get(req.userId).coin_balance;
      result = { insufficient: false, sendId, createdAt: now, senderCoinBalance };
    });
    tx();
  } catch (dbErr) {
    console.error("[POST /api/livestreams/:id/gifts] 出错:", dbErr);
    return res.status(500).json({ error: "送礼物失败,请稍后重试" });
  }

  if (result.insufficient) {
    return res.status(402).json({ error: "金币余额不足,请先充值", code: "INSUFFICIENT_COINS" });
  }

  const sender = db.prepare("SELECT id, username, display_name, avatar_url FROM users WHERE id = ?").get(req.userId);
  const payload = {
    livestreamId,
    sendId: result.sendId,
    gift: { id: gift.id, name: gift.name, icon: gift.icon, coinPrice: gift.coin_price },
    quantity,
    coinCost,
    sender: sender ? { id: sender.id, username: sender.username, displayName: sender.display_name, avatarUrl: sender.avatar_url } : null,
    createdAt: result.createdAt,
  };
  io.to(`live:${livestreamId}`).emit("live_gift", payload);

  createNotification({
    userId: live.host_id, type: "tip", actorId: req.userId,
    content: `${sender?.display_name || sender?.username || "有人"} 送出了 ${gift.icon}${gift.name} x${quantity}`,
  });

  res.json({ ok: true, senderCoinBalance: result.senderCoinBalance });
});

// 背景音乐曲库:公开可查,url 是相对路径(比如 /music/xxx.mp3),由上面的
// express.static 中间件直接提供文件,前端自己拼上 backendUrl() 前缀播放。
app.get("/api/music/tracks", optionalAuth, (req, res) => {
  const tracks = db.prepare(`
    SELECT id, title, artist, url, duration_seconds AS durationSeconds
    FROM music_tracks WHERE is_active = 1 ORDER BY sort_order ASC
  `).all();
  res.json({ tracks });
});

/* =========================================================================
   Socket.io 实时消息推送

   ⚠️ 本轮核心修复:不再有自由声明身份的 `identify` 事件。身份验证挪到
   连接握手阶段(io.use 中间件),客户端连接时必须在 `auth.token` 里带上
   有效的 accessToken,验证不通过直接拒绝连接,拿到 socket 之后
   socket.data.userId 就是服务端验证过的真实身份,不可能被伪造。
   ========================================================================= */
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("未登录:缺少 accessToken"));
  try {
    const payload = verifySession(token, SESSION_SECRET);
    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(payload.sub);
    if (!user) return next(new Error("账号不存在"));
    socket.data.userId = payload.sub;
    next();
  } catch (e) {
    next(new Error("accessToken 无效或已过期"));
  }
});

io.on("connection", (socket) => {
  socket.join(`user:${socket.data.userId}`);

  socket.on("send_message", (payload, ack) => {
    try {
      const { conversationId, content, messageType } = payload || {};
      const senderId = socket.data.userId;

      if (!conversationId || typeof content !== "string" || !content.trim()) {
        return ack && ack({ error: "conversationId 和 content 均为必填" });
      }
      if (content.length > 2000) return ack && ack({ error: "消息内容过长" });
      const allowedTypes = ["text", "image", "system"];
      const type = allowedTypes.includes(messageType) ? messageType : "text";

      const isMember = db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?").get(conversationId, senderId);
      if (!isMember) return ack && ack({ error: "你不是该会话成员" });

      const message = {
        id: uuidv4(), conversation_id: conversationId, sender_id: senderId,
        content: content.trim(), message_type: type, created_at: Date.now(),
      };
      db.prepare(`
        INSERT INTO messages (id, conversation_id, sender_id, content, message_type, created_at)
        VALUES (@id, @conversation_id, @sender_id, @content, @message_type, @created_at)
      `).run(message);

      const members = db.prepare("SELECT user_id FROM conversation_members WHERE conversation_id = ?").all(conversationId);
      members.forEach(({ user_id }) => io.to(`user:${user_id}`).emit("new_message", message));

      ack && ack({ ok: true, message });
    } catch (err) {
      console.error("[socket send_message] 出错:", err);
      ack && ack({ error: "服务端处理消息时出错" });
    }
  });

  socket.on("typing", ({ conversationId } = {}) => {
    try {
      const senderId = socket.data.userId;
      if (!conversationId) return;
      const members = db.prepare("SELECT user_id FROM conversation_members WHERE conversation_id = ? AND user_id != ?").all(conversationId, senderId);
      members.forEach(({ user_id }) => io.to(`user:${user_id}`).emit("typing", { conversationId, userId: senderId }));
    } catch (err) {
      console.error("[socket typing] 出错:", err);
    }
  });

  // -----------------------------------------------------------------------
  // 直播间(本轮新增):聊天消息 + 点赞飘心,走同一条 socket 连接,
  // 用 `live:${livestreamId}` 房间隔离,和私信/群聊的 `user:${userId}` 房间
  // 互不影响。真正的音视频画面/声音不走这条通道,走 LiveKit。
  // -----------------------------------------------------------------------
  socket.on("join_live_room", ({ livestreamId } = {}, ack) => {
    try {
      if (!livestreamId) return ack && ack({ error: "缺少 livestreamId" });
      const live = db.prepare("SELECT id, status FROM livestreams WHERE id = ?").get(livestreamId);
      if (!live || live.status !== "live") return ack && ack({ error: "直播不存在或已结束" });
      socket.join(`live:${livestreamId}`);
      socket.data.currentLiveRoom = livestreamId;
      const viewerCount = io.sockets.adapter.rooms.get(`live:${livestreamId}`)?.size || 0;
      // 峰值人数只是个粗略统计(给主播/后台看个大概),不是精确的实时在线来源
      db.prepare("UPDATE livestreams SET peak_viewer_count = MAX(peak_viewer_count, ?) WHERE id = ?").run(viewerCount, livestreamId);
      io.to(`live:${livestreamId}`).emit("live_viewer_count", { livestreamId, viewerCount });
      ack && ack({ ok: true, viewerCount });
    } catch (err) {
      console.error("[socket join_live_room] 出错:", err);
      ack && ack({ error: "加入直播间失败" });
    }
  });

  socket.on("leave_live_room", ({ livestreamId } = {}) => {
    if (!livestreamId) return;
    socket.leave(`live:${livestreamId}`);
    if (socket.data.currentLiveRoom === livestreamId) socket.data.currentLiveRoom = null;
    const viewerCount = io.sockets.adapter.rooms.get(`live:${livestreamId}`)?.size || 0;
    io.to(`live:${livestreamId}`).emit("live_viewer_count", { livestreamId, viewerCount });
  });

  socket.on("live_chat_message", ({ livestreamId, content } = {}, ack) => {
    try {
      if (!livestreamId || typeof content !== "string" || !content.trim()) return ack && ack({ error: "内容不能为空" });
      if (!socket.rooms.has(`live:${livestreamId}`)) return ack && ack({ error: "还没有加入这个直播间" });
      const trimmed = content.trim().slice(0, 300);
      const sender = db.prepare("SELECT id, username, display_name, avatar_url FROM users WHERE id = ?").get(socket.data.userId);
      const payload = {
        livestreamId,
        id: uuidv4(),
        content: trimmed,
        createdAt: Date.now(),
        sender: sender
          ? { id: sender.id, username: sender.username, displayName: sender.display_name, avatarUrl: sender.avatar_url }
          : { id: socket.data.userId },
      };
      io.to(`live:${livestreamId}`).emit("live_chat_message", payload);
      ack && ack({ ok: true });
    } catch (err) {
      console.error("[socket live_chat_message] 出错:", err);
      ack && ack({ error: "发送失败" });
    }
  });

  // 点赞飘心:纯前端动效用的信号,不落库,只做一个简单的按连接节流,防止连点刷屏
  socket.on("live_heart", ({ livestreamId } = {}) => {
    if (!livestreamId) return;
    if (!socket.rooms.has(`live:${livestreamId}`)) return;
    const now = Date.now();
    if (socket.data.lastHeartAt && now - socket.data.lastHeartAt < 150) return;
    socket.data.lastHeartAt = now;
    io.to(`live:${livestreamId}`).emit("live_heart", { livestreamId, userId: socket.data.userId });
  });

  socket.on("disconnect", () => {
    // 预留:可在这里做"最后在线时间"更新等逻辑
    if (socket.data.currentLiveRoom) {
      const livestreamId = socket.data.currentLiveRoom;
      // 等 socket 真正从房间里移除之后再统计人数,避免把自己也算进"离开后还剩几人"里
      setImmediate(() => {
        const viewerCount = io.sockets.adapter.rooms.get(`live:${livestreamId}`)?.size || 0;
        io.to(`live:${livestreamId}`).emit("live_viewer_count", { livestreamId, viewerCount });
      });
    }
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Ownlo 后端服务已启动: http://localhost:${PORT}`);
  console.log(`PI_API_KEY: ${process.env.PI_API_KEY ? "已配置" : "⚠️ 未配置"}`);
  console.log(`GOOGLE_CLIENT_ID: ${process.env.GOOGLE_CLIENT_ID && !process.env.GOOGLE_CLIENT_ID.includes("YOUR_GOOGLE") ? "已配置" : "⚠️ 未配置,Google 登录将被拒绝"}`);
  console.log(`RESEND_API_KEY: ${RESEND_API_KEY ? "已配置" : "⚠️ 未配置,邮箱验证码仅打印到日志"}`);
  console.log(`CORS_ALLOWED_ORIGINS: ${allowedOrigins.length ? allowedOrigins.join(", ") : "⚠️ 未配置,当前允许任意来源"}`);
  console.log(`REQUIRE_VIDEO_REVIEW: ${REQUIRE_VIDEO_REVIEW}`);
  console.log(`LIVEKIT: ${LIVEKIT_URL && LIVEKIT_API_KEY && LIVEKIT_API_SECRET ? "已配置" : "⚠️ 未配置,直播相关接口会返回 503"}`);
});
