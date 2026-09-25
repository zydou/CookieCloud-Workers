# CookieCloud Cloudflare Worker

[CookieCloud](https://github.com/easychen/CookieCloud) 服务端的 Cloudflare Workers 兼容实现，完全对齐 `api/app.js` 的 API，让现有 Chrome 扩展（以及 PyCookieCloud / playwright
等第三方客户端）**零改动**直接指向 Worker。

- **存储**：R2（免费版 10GB + 100 万次写/1000 万次读每月）
- **解密**：`node:crypto`（Workers 原生、硬件加速），无需任何运行时依赖
- **免费版限制**：上传/下载路径 CPU 消耗 1-5ms（限制 10ms），2MB 密文服务端解密 < 6ms

## 端到端加密说明

服务端只存储密文，扩展端在本地解密（password 从不发给服务器）。
`POST /get/:uuid` 带 password 时的服务端解密仅服务于第三方无头客户端，两种算法均已支持：

- `legacy`（CryptoJS 字符串 key 格式）：`Salted__` 前缀 + EVP_BytesToKey（MD5, **AES-256-CBC**）派生 key/iv
- `aes-128-cbc-fixed`：md5(key) + 全零 IV 的标准 **AES-128-CBC**

## 本地开发与测试

```bash
pnpm install
pnpm typecheck     # TypeScript 类型检查
pnpm wrangler dev  # 本地启动 (http://localhost:8787), R2 由 miniflare 模拟
pnpm test          # 另开终端: 端到端冒烟测试 (模拟扩展端协议)
```

## 部署

```bash
pnpm wrangler r2 bucket create cookiecloud   # 首次一次性创建 R2 bucket (bucket 名全局唯一, 可改名)
pnpm wrangler deploy
```

凭证通过环境变量提供（wrangler 标准支持，仓库根 `.env` 已有）：

```bash
export CLOUDFLARE_ACCOUNT_ID=...
export CLOUDFLARE_API_TOKEN=...
```

部署完成后，把扩展端设置页的 **endpoint** 改为 `https://cookiecloud.<your-subdomain>.workers.dev` 即可（其余配置不变）。

### 可选配置（`wrangler.toml`）

| 配置                     | 说明 |
| ------------------------ | ---- |
| `[vars] API_ROOT`        | 与原 Express 服务端 `API_ROOT` 一致的可选子路径前缀，留空则绑定根路径 |
| `workers_dev` / `routes` | 默认使用 `<name>.<subdomain>.workers.dev`；绑定自定义域需在 `routes` 配置 |

### 已对齐的原服务端行为

- `GET /health`、`GET /`、`POST /update`、`GET|POST /get/:uuid`
- gzip 请求体（扩展端上传压缩）、JSON 与 urlencoded body
- 缺字段 → 400、不存在 → 404、解密失败 → 500
- CORS 全开、15 分钟 100 次/IP 内存限流
- `crypto_type` 优先级：查询参数 > 存储值 > `legacy`
