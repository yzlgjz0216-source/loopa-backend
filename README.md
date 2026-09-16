# Ownlo MVP — 登录 + Feed 原型

## 这是什么
Ownlo 产品的第一版可运行原型,包含:
- **四种登录方式**:Pi 钱包(`Pi.authenticate`)、Google 账号(Google Identity Services)、Solana 钱包(检测 `window.solana`,如 Phantom)、手机号(占位,待接短信服务商)
- 统一身份管理模块 `AuthManager`,把四种登录方式映射到同一个平台账户(后端待实现)
- 短视频 Feed 流 UI(占位数据,竖屏沉浸式)
- 打赏弹层 UI(PI 已接通真实支付调用链路;USDT/USDC 为占位,等合规评估完成后再实现)
- 代币/积分模块预留结构 `OwnloToken`(**未实现任何发币逻辑**,见下方"代币发行"说明)
- **私信+群聊界面**(`ChatClient`),可对接 `loopa-backend` 项目实现真实实时聊天,本地未连后端时自动降级为模拟数据演示
- **10种语言界面切换**(`i18n.js`):繁体中文、English、한국어、日本語、Tiếng Việt、العربية、Bahasa Indonesia、हिन्दी、Filipino、اردو,右上角下拉框切换,自动记住选择,阿拉伯语/乌尔都语会自动切换成从右到左(RTL)布局

**不包含**:真实视频播放/上传/CDN、真实的 USDT/USDC 链上转账逻辑、任何链上代币发行。聊天后端见独立的 `loopa-backend` 项目。

⚠️ **多语言翻译质量提醒**:`i18n.js` 里的翻译是AI生成的首版内容,正式上线前建议找母语者校对,尤其是阿拉伯语(ar)和乌尔都语(ur)。

## ⚠️ 关于代币发行(Solana / Pi 上发币)
代码里只留了 `OwnloToken` 的空结构和注释,**没有实现任何发币功能**,原因:

一个可对外交易、有市场价格的代币,在多数司法辖区可能被认定为具有证券属性(如美国的 Howey Test),适用的合规要求远高于单纯接受 USDT/USDC 打赏。这件事必须先经过专门的法律评估,不能靠技术团队自行判断,更不能靠 AI 审查代替。

**当前阶段的正确做法**:先用平台内部积分(不可对外交易、不可提现为链上代币)跑通产品和经济模型,代币发行留到法律评估通过后再单独启动。

## 如何连接真实的聊天后端
1. 按 `loopa-backend` 项目的 README 先把后端跑起来(本地或服务器)
2. 打开 `index.html`,取消 `<head>` 里 Socket.io CDN 那行的注释
3. 打开 `app.js`,把 `ChatClient` 模块里的 `BACKEND_URL` 改成你的后端实际地址
4. 刷新页面,登录后点右上角聊天图标,即可发出真实的、通过后端持久化并实时推送的消息

## 如何预览
本地浏览器直接打开 `index.html` 即可看到界面效果(会自动进入"本地模拟模式",登录按钮点击后用假数据代替真实 Pi 登录,方便你不用每次都进 Pi Browser 测试 UI)。

要测试真实的 Pi 登录/支付流程,需要:
1. 在 [Pi 开发者后台](https://developers.minepi.com) 注册你的 App,拿到 App 的开发者配置
2. 把这个项目部署到一个公网可访问的 URL(HTTPS)
3. 在 Pi Browser 里打开这个 URL 进行测试
4. `app.js` 里的 `sandbox: true` 目前指向 Pi 的 Testnet 沙盒环境,正式上线前需要改成 `false` 并完成 Pi 官方的正式审核

## 代码结构与多AI交叉审查建议

| 文件/模块 | 说明 | 是否为支付关键模块(需重点审查) |
|---|---|---|
| `index.html` | 页面结构 | 否 |
| `style.css` | 视觉样式 | 否 |
| `app.js` → `PiAuth` | Pi 登录集成 | **是** |
| `app.js` → `GoogleAuth` | Google OAuth登录 | **是**(涉及JWT校验) |
| `app.js` → `SolanaAuth` | Solana钱包连接 | **是**(涉及签名验证) |
| `app.js` → `BNBAuth` | BNB Chain钱包连接 | **是**(涉及签名验证) |
| `app.js` → `AgeGate` | 年龄门槛与未成年人保护 | **是**(前端判断可被绕过,后端必须重复校验) |
| `app.js` → `BiometricAuth` | 指纹/面容快捷登录(WebAuthn) | **是**(challenge目前硬编码,后端必须改成真实一次性随机值) |
| `app.js` → `EmbeddedWallet` | 嵌入式钱包(占位,未实现) | **是**(实现前必须先选定Privy/Web3Auth等服务商并完成法律评估) |
| `app.js` → `PhoneAuth` | 手机号登录(占位) | 是(实现短信校验时) |
| `app.js` → `AuthManager` | 多身份统一绑定 | **是**(账户安全核心逻辑) |
| `app.js` → `renderFeed` | Feed渲染(占位数据) | 否 |
| `app.js` → `TipSheet.payWithPi` | Pi 支付调用 | **是** |
| `app.js` → `TipSheet.payWithStablecoin` | 稳定币打赏(仅占位,未实现) | 是(实现时) |
| `app.js` → `OwnloToken` | 代币发行(仅空结构,未实现) | 是(实现前必须先完成法律评估) |

**建议交给 DeepSeek / GPT-6 交叉审查时,重点丢给它们 `PiAuth` 和 `payWithPi` 这两块**,重点关注:
- `accessToken` 有没有在前端被不当存储或泄露风险
- 支付回调(`onReadyForServerApproval` / `onReadyForServerCompletion`)里标注的 TODO 后端联调点,是否有遗漏的校验环节(比如有没有可能被重放攻击、重复入账)
- `sandbox` 开关、`scope` 权限申请是否有过度索取

## 待办事项(标注在代码注释里的 TODO)
- [ ] 后端 `/api/auth/pi-verify`:验证 accessToken 真实性
- [ ] 后端 `/api/payments/approve`、`/api/payments/complete`:对接 Pi 服务端支付确认接口
- [ ] 未完成支付的补单逻辑(`onIncompletePaymentFound`)
- [ ] USDT/USDC 打赏:WalletConnect 接入(合规评估通过后启动)
- [ ] 真实视频流:接入 CDN + 播放器(建议用 HLS.js 或类似方案替换当前的占位色块背景)

## 上线前必做(参考 PRD 风险清单)
- [ ] 支付相关代码经过一次性专业第三方安全审计(不只是多AI审查)
- [ ] 商标查重与注册完成
- [ ] 公司主体注册完成
- [ ] KYC/AML 合规评估完成(尤其是稳定币打赏部分)
