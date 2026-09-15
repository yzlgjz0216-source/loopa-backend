# Loopa 后端服务(MVP) — 私信 + 群聊

## 这是什么
一个可以直接运行的 Node.js 后端服务,实现:
- 用户表(简化版,测试用)
- 私信会话(自动去重,两人之间只会有一个会话)
- 群聊会话(建群、拉人)
- 消息发送与历史记录拉取(分页)
- 已读状态与未读消息计数
- 基于 Socket.io 的实时消息推送(发消息后,对方在线会立刻收到,不需要刷新页面)

## 本地如何运行
需要你的电脑或服务器上已安装 [Node.js](https://nodejs.org)(建议 18版本以上)。

```bash
cd loopa-backend
npm install
cp .env.example .env
npm start
```

看到终端输出 `Loopa 后端服务已启动: http://localhost:4000` 就说明跑起来了。

## ⚠️ 上线前必须解决的安全问题(重点标注,供技术顾问/多AI审查时重点检查)

**当前的身份验证是"假的"，只适合本地开发阶段联调测试：**

- REST接口靠请求头 `x-user-id` 直接信任身份,Socket.io靠客户端自己上报的 `userId` 直接信任
- **这意味着现在任何人只要知道别人的 user id,就能伪造身份读别人的聊天记录、冒充别人发消息**
- 正式上线前,必须把这里换成真实校验:前端应该把登录时拿到的凭证(Pi的accessToken / Google的credential / Solana签名)传给后端,后端逐一验证有效性后,才能确定"这个请求真的是这个用户发出的"

对应到代码里,需要重点修改的位置是 `server.js` 里的 `requireAuth()` 函数和 Socket.io 的 `identify` 事件处理逻辑,这两处建议列为多AI交叉审查和最终安全审计的**最高优先级**检查项,不能跳过。

## 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/users` | 创建测试用户 |
| POST | `/api/payments/approve` | 批准一笔 Pi 支付(需配置 `PI_API_KEY`),批准成功后写入打赏流水表 |
| POST | `/api/payments/complete` | 确认一笔 Pi 支付完成(需配置 `PI_API_KEY`),完成后更新流水状态并累加创作者收益 |
| GET | `/api/creators/:name/balance` | 查询某个创作者的累计打赏收益(个人主页"创作者收益"标签用) |
| GET | `/api/conversations` | 获取当前用户的会话列表 |
| POST | `/api/conversations/direct` | 创建/获取与某人的私信会话 |
| POST | `/api/conversations/group` | 创建群聊 |
| GET | `/api/conversations/:id/messages` | 拉取会话历史消息(分页) |
| POST | `/api/conversations/:id/read` | 标记已读 |

Socket.io 事件:
- `identify(userId)` — 客户端连接后表明身份
- `send_message({conversationId, content})` — 发送消息
- `new_message` — 服务端推送新消息给客户端监听
- `typing({conversationId})` — 正在输入提示

## 部署到你的云服务器(对照之前的《部署操作指南》Part B)
1. 把这个 `loopa-backend` 文件夹上传到服务器
2. 服务器上执行 `npm install`
3. 用 PM2 让服务常驻:`pm2 start server.js --name loopa-backend`
4. Nginx 配置反向代理,把 `api.loopa.plus`(或你自己定的域名)的请求转发到 `localhost:4000`
5. 用 Certbot 给这个子域名签发HTTPS证书

## 下一步待办
- [x] 打赏流水表(`tips`)+ 创作者收益汇总(`creator_balances`)已接入,PI打赏在Pi官方确认后会真实入账
- [ ] 把 `requireAuth` 换成真实的身份验证(接入前端 AuthManager 的登录凭证校验)
- [ ] 用户量上来后,评估从 SQLite 迁移到 PostgreSQL(表结构已尽量按标准SQL写,迁移成本较低)
- [ ] 前端聊天界面对接(见 `loopa-mvp` 项目里新增的 Chat 模块)
- [ ] 群聊的"踢人/退群/管理员权限"等管理功能(当前只有基础建群/拉人)
- [ ] 消息支持图片/文件(当前 `message_type` 字段已预留,尚未实现上传逻辑)
- [ ] USDT/USDC打赏接入后,`tips`表的`currency`字段已预留,可直接复用同一张表记录
- [ ] 切换到Mainnet时:改`app.js`里`sandbox:false` + 换成Mainnet版本的`PI_API_KEY`,数据库和业务逻辑不需要改动
