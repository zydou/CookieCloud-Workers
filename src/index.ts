import { cookieDecrypt } from './crypto';

// R2 最小接口 (仅使用 get/put), 避免引入 @cloudflare/workers-types 与 @types/node 的全局类型冲突
interface R2ObjectBody {
  text(): Promise<string>;
}

interface R2Bucket {
  get(key: string): Promise<R2ObjectBody | null>;
  put(key: string, value: string): Promise<unknown>;
}

interface Env {
  COOKIE_BUCKET: R2Bucket;
  API_ROOT?: string;
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  // 必须放行扩展端上传使用的 Content-Encoding / Content-Type
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400',
};

// 与原服务端 express-rate-limit 对齐: 15 分钟窗口内每 IP 最多 100 次
// 仅按 Cloudflare 边缘 IP 计数, 跨 isolate 不共享, 个人使用足够
const RATE_LIMIT = { windowMs: 15 * 60 * 1000, max: 100 };
const rateMap = new Map<string, { count: number; windowStart: number }>();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  if (rateMap.size > 5000) {
    // 防止 Map 无限增长: 清理已过期窗口
    for (const [key, entry] of rateMap) {
      if (now - entry.windowStart >= RATE_LIMIT.windowMs) rateMap.delete(key);
    }
  }
  const entry = rateMap.get(ip);
  if (!entry || now - entry.windowStart >= RATE_LIMIT.windowMs) {
    rateMap.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT.max;
}

/** 清洗 uuid 为安全的 R2 key 名: 等价原服务端 path.basename 语义并进一步收紧字符集 */
function sanitizeUuid(uuid: string): string {
  const base = uuid.substring(uuid.lastIndexOf('/') + 1); // path.basename
  return base.replace(/[^A-Za-z0-9._-]/g, '');
}

/** 读取请求体。Workers 不会自动解压请求体, 必须手动处理 Content-Encoding: gzip */
async function readBody(request: Request): Promise<Buffer> {
  const encoding = request.headers.get('Content-Encoding') || '';
  if (encoding.includes('gzip')) {
    const stream = request.body!.pipeThrough(new DecompressionStream('gzip'));
    return Buffer.from(await new Response(stream).arrayBuffer());
  }
  return Buffer.from(await request.arrayBuffer());
}

/** 从 POST body 读取 password, 兼容 JSON 与 application/x-www-form-urlencoded */
async function readPassword(request: Request): Promise<string | undefined> {
  const contentType = request.headers.get('Content-Type') || '';
  const text = (await readBody(request)).toString('utf8');
  if (!text) return undefined;
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return new URLSearchParams(text).get('password') || undefined;
  }
  try {
    const obj = JSON.parse(text);
    return typeof obj?.password === 'string' ? obj.password : undefined;
  } catch {
    return undefined;
  }
}

function withCors(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [key, value] of Object.entries(CORS_HEADERS)) out.headers.set(key, value);
  return out;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function handleUpdate(request: Request, env: Env): Promise<Response> {
  try {
    const raw = await readBody(request);
    const body = JSON.parse(raw.toString('utf8')) as { uuid?: string; encrypted?: string; crypto_type?: string };
    if (!body.encrypted || !body.uuid) {
      return withCors(new Response('Bad Request', { status: 400 }));
    }
    const key = sanitizeUuid(body.uuid) + '.json';
    // 与原服务端一致: crypto_type 缺省时省略该字段 (客户端 fallback 到 legacy)
    const content = JSON.stringify({ encrypted: body.encrypted, crypto_type: body.crypto_type });
    await env.COOKIE_BUCKET.put(key, content);
    return withCors(json({ action: 'done' }));
  } catch (error) {
    console.error('update error:', error);
    return withCors(json({ action: 'error' }));
  }
}

async function handleGet(request: Request, env: Env, uuidParam: string): Promise<Response> {
  try {
    const key = sanitizeUuid(uuidParam) + '.json';
    const obj = await env.COOKIE_BUCKET.get(key);
    if (!obj) {
      return withCors(new Response('Not Found', { status: 404 }));
    }
    const data = JSON.parse(await obj.text()) as { encrypted: string; crypto_type?: string };

    // password 仅 POST 请求有意义 (GET 无 body)
    let password: string | undefined;
    if (request.method === 'POST') {
      password = await readPassword(request);
    }

    if (password) {
      // crypto_type 优先级: 查询参数 > 存储值 > legacy
      const cryptoType =
        new URL(request.url).searchParams.get('crypto_type') || data.crypto_type || 'legacy';
      const parsed = cookieDecrypt(uuidParam, data.encrypted, password, cryptoType);
      return withCors(json(parsed));
    }

    return withCors(json(data));
  } catch (error) {
    console.error('get error:', error);
    return withCors(new Response('Internal Serverless Error', { status: 500 }));
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // 限流
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!rateLimit(ip)) {
      return withCors(new Response('Too Many Requests', { status: 429 }));
    }

    const url = new URL(request.url);
    let path = url.pathname;

    // API_ROOT 可选前缀 (对齐原服务端 API_ROOT=/cookie 用法)
    const apiRoot = (env.API_ROOT || '').trim().replace(/\/+$/, '');
    if (apiRoot) {
      if (path === apiRoot) {
        path = '/';
      } else if (path.startsWith(apiRoot + '/')) {
        path = path.substring(apiRoot.length);
      }
    }

    // 根路径 / 健康检查
    if (request.method === 'GET' && path === '/') {
      return withCors(json({ message: `Hello World! API ROOT = ${apiRoot}` }));
    }
    if (request.method === 'GET' && path === '/health') {
      return withCors(json({ status: 'OK', timestamp: new Date().toISOString(), uptime: 0 }));
    }

    // 上传
    if (request.method === 'POST' && path === '/update') {
      return handleUpdate(request, env);
    }

    // 下载 (GET 返回密文; POST 带 password 时服务端解密)
    const getMatch = path.match(/^\/get\/([^/]+)$/);
    if (getMatch && (request.method === 'GET' || request.method === 'POST')) {
      return handleGet(request, env, getMatch[1]);
    }

    return withCors(new Response('Not Found', { status: 404 }));
  },
};
