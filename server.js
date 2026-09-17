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
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
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

function publicUserView(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url,
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

        const tip = db.prepare("SELECT amount, amount_units, creator_user_id, creator_name FROM tips WHERE payment_id = ?").get(paymentId);
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

// 查询某个创作者的累计打赏收益。优先用 creator_user_id(v2表,真正的记账依据),
// 传的是 username 时先查出对应的 user id 再查,兼容前端仍按用户名展示的场景。
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

  const videos = req.userId
    ? db.prepare(`
        SELECT v.id, v.creator_id, v.creator_name, v.caption, v.video_url, v.thumbnail_url, v.view_count, v.like_count, v.created_at,
               (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS comment_count
        FROM videos v
        WHERE v.status = 'published' AND v.created_at < ?
          AND v.creator_id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
          AND v.creator_id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
        ORDER BY v.created_at DESC LIMIT ?
      `).all(before, req.userId, req.userId, limit)
    : db.prepare(`
        SELECT id, creator_id, creator_name, caption, video_url, thumbnail_url, view_count, like_count, created_at,
               (SELECT COUNT(*) FROM comments WHERE video_id = videos.id) AS comment_count
        FROM videos WHERE status = 'published' AND created_at < ?
        ORDER BY created_at DESC LIMIT ?
      `).all(before, limit);

  res.json(videos);
});

app.get("/api/videos/user/:creatorId", (req, res) => {
  const videos = db.prepare(`
    SELECT id, caption, video_url, thumbnail_url, view_count, like_count, created_at,
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

  const video = db.prepare("SELECT id, like_count FROM videos WHERE id = ?").get(videoId);
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

  const updated = db.prepare("SELECT like_count FROM videos WHERE id = ?").get(videoId);
  res.json({ liked: !existing, likeCount: updated.like_count });
});

app.get("/api/users/:userId/likes", (req, res) => {
  const rows = db.prepare("SELECT video_id FROM likes WHERE user_id = ?").all(req.params.userId);
  res.json(rows.map((r) => r.video_id));
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
  }

  const followerCount = db.prepare("SELECT COUNT(*) AS c FROM follows WHERE creator_id = ?").get(creatorId).c;
  res.json({ following: !existing, followerCount });
});

app.get("/api/users/:userId/following", (req, res) => {
  const rows = db.prepare("SELECT creator_id FROM follows WHERE follower_id = ?").all(req.params.userId);
  res.json(rows.map((r) => r.creator_id));
});

/* =========================================================================
   评论
   ========================================================================= */
app.get("/api/videos/:id/comments", (req, res) => {
  const comments = db.prepare(`
    SELECT id, user_id, username, content, created_at FROM comments WHERE video_id = ? ORDER BY created_at ASC
  `).all(req.params.id);
  res.json(comments);
});

app.post("/api/videos/:id/comments", requireAuth, commentLimiter, (req, res) => {
  const { content } = req.body;
  if (!content || !String(content).trim()) return res.status(400).json({ error: "content 必填" });

  const video = db.prepare("SELECT id FROM videos WHERE id = ?").get(req.params.id);
  if (!video) return res.status(404).json({ error: "视频不存在" });

  const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(req.userId);
  if (!user) return res.status(401).json({ error: "账号不存在" });

  const comment = {
    id: uuidv4(), video_id: req.params.id, user_id: user.id, username: user.username,
    content: String(content).trim().slice(0, 500), created_at: Date.now(),
  };
  db.prepare(`
    INSERT INTO comments (id, video_id, user_id, username, content, created_at)
    VALUES (@id, @video_id, @user_id, @username, @content, @created_at)
  `).run(comment);

  res.json(comment);
});

/* =========================================================================
   个人资料
   ========================================================================= */
app.patch("/api/users/:id", requireAuth, (req, res) => {
  if (req.params.id !== req.userId) return res.status(403).json({ error: "只能修改自己的资料" });
  const { displayName, bio } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });

  const nextDisplayName = (displayName || "").trim().slice(0, 40) || user.display_name;
  const nextBio = (bio || "").trim().slice(0, 200);

  db.prepare("UPDATE users SET display_name = ?, bio = ? WHERE id = ?").run(nextDisplayName, nextBio, req.params.id);
  const updated = db.prepare("SELECT id, username, display_name, avatar_url, bio FROM users WHERE id = ?").get(req.params.id);
  res.json(updated);
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
app.get("/api/conversations", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.type, c.group_name, c.group_avatar_url,
      (SELECT content FROM messages WHERE conversation_id = c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_message_at,
      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.created_at > cm.last_read_at) AS unread_count
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id
    WHERE cm.user_id = ?
    ORDER BY last_message_at DESC
  `).all(req.userId);
  res.json(rows);
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

  const isMember = db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?").get(id, req.userId);
  if (!isMember) return res.status(403).json({ error: "你不是该会话成员" });

  const messages = db.prepare(`
    SELECT * FROM messages WHERE conversation_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?
  `).all(id, before, limit);
  res.json(messages.reverse());
});

app.post("/api/conversations/:id/read", requireAuth, (req, res) => {
  db.prepare("UPDATE conversation_members SET last_read_at = ? WHERE conversation_id = ? AND user_id = ?")
    .run(Date.now(), req.params.id, req.userId);
  res.json({ ok: true });
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

  socket.on("disconnect", () => {
    // 预留:可在这里做"最后在线时间"更新等逻辑
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
});
