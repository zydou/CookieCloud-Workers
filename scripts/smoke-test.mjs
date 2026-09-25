/**
 * 端到端冒烟测试: 模拟 Chrome 扩展端协议 (ext/utils/functions.ts) 验证 Worker 兼容性。
 *
 * 用法:
 *   1. 终端 A: pnpm wrangler dev (默认 http://localhost:8787)
 *   2. 终端 B: BASE_URL=http://localhost:8787 node scripts/smoke-test.mjs
 *   3. 部署后: BASE_URL=https://cookiecloud.<subdomain>.workers.dev node scripts/smoke-test.mjs
 *
 * 注意: 在需要代理才能访问外网的环境, 为 Node 的 fetch 添加 NODE_USE_ENV_PROXY=1
 * (Node 的 fetch 默认不遵循 HTTP_PROXY/HTTPS_PROXY 环境变量)。
 */
import CryptoJS from 'crypto-js';
import { gzip } from 'pako';

const BASE = (process.env.BASE_URL || 'http://localhost:8787').replace(/\/+$/, '');

let passed = 0;
let failed = 0;

function assert(cond, label) {
  if (cond) {
    passed++;
    console.log(`  ✅ ${label}`);
  } else {
    failed++;
    console.error(`  ❌ ${label}`);
  }
}

// ---- 与扩展端 functions.ts cookie_encrypt 完全一致的加密 ----
function cookieEncrypt(uuid, dataString, password, cryptoType) {
  const hash = CryptoJS.MD5(uuid + '-' + password).toString();
  const theKey = hash.substring(0, 16);
  if (cryptoType === 'aes-128-cbc-fixed') {
    const fixedIv = CryptoJS.enc.Hex.parse('00000000000000000000000000000000');
    const enc = CryptoJS.AES.encrypt(dataString, CryptoJS.enc.Utf8.parse(theKey), {
      iv: fixedIv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return enc.ciphertext.toString(CryptoJS.enc.Base64);
  }
  return CryptoJS.AES.encrypt(dataString, theKey).toString();
}

// ---- 与扩展端 upload_cookie 一致的 gzip 上传 ----
async function upload(uuid, encrypted, cryptoType) {
  const body = gzip(JSON.stringify({ uuid, encrypted, crypto_type: cryptoType }));
  const res = await fetch(`${BASE}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    body,
  });
  return { status: res.status, data: await res.json() };
}

const sampleData = JSON.stringify({
  cookie_data: {
    'example.com': [
      {
        name: 'sid',
        value: 'abc123',
        domain: '.example.com',
        path: '/',
        secure: true,
        httpOnly: false,
        sameSite: 'lax',
      },
    ],
  },
  local_storage_data: { 'example.com': { 'user-token': 'xyz' } },
  update_time: '2026-01-01T00:00:00.000Z',
});

console.log(`\n测试目标: ${BASE}\n`);

for (const type of ['legacy', 'aes-128-cbc-fixed']) {
  console.log(`--- crypto_type = ${type} ---`);
  const uuid = `test-${type}-${Math.random().toString(36).slice(2, 8)}`;
  const password = 'test-password';

  // 1. 上传
  const encrypted = cookieEncrypt(uuid, sampleData, password, type);
  const up = await upload(uuid, encrypted, type);
  assert(up.status === 200 && up.data.action === 'done', `上传成功返回 {"action":"done"} (status=${up.status})`);

  // 2. 下载 (扩展端路径: GET 不带 password, 本地解密)
  const dl = await fetch(`${BASE}/get/${uuid}`, { method: 'GET', headers: { 'Content-Type': 'application/json' } });
  const dlData = await dl.json();
  assert(dl.status === 200 && dlData.encrypted === encrypted, `GET 下载返回密文一致 (status=${dl.status})`);
  assert(dlData.crypto_type === type, `GET 下载返回 crypto_type=${dlData.crypto_type}`);

  // 3. 服务端解密 (第三方路径: POST 带 password)
  const dec = await fetch(`${BASE}/get/${uuid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  const decData = await dec.json();
  assert(
    dec.status === 200 && JSON.stringify(decData) === sampleData,
    `POST 带 password 服务端解密还原明文 (status=${dec.status})`
  );
  console.log('');
}

console.log('--- 错误路径 ---');
const nf = await fetch(`${BASE}/get/does-not-exist-xyz`, { method: 'GET' });
assert(nf.status === 404, `不存在的 uuid 返回 404 (status=${nf.status})`);

const bad = await fetch(`${BASE}/update`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ encrypted: 'x' }), // 缺 uuid
});
assert(bad.status === 400, `缺 uuid 的上传返回 400 (status=${bad.status})`);

// legacy 模式不带 crypto_type 上传 (存储缺省 fallback)
console.log('\n--- legacy 缺省 crypto_type ---');
const uuid2 = `test-nocryptotype-${Math.random().toString(36).slice(2, 8)}`;
const enc2 = cookieEncrypt(uuid2, sampleData, 'pw', 'legacy');
const up2 = await upload(uuid2, enc2, undefined);
assert(up2.status === 200 && up2.data.action === 'done', 'legacy 不带 crypto_type 上传成功');
const dl2 = await fetch(`${BASE}/get/${uuid2}`);
const dl2Data = await dl2.json();
assert(dl2.status === 200 && dl2Data.encrypted === enc2 && !dl2Data.crypto_type, '存储缺省 crypto_type 字段省略 (与原生一致)');

// urlencoded 形式的 password
console.log('\n--- urlencoded password 兼容 ---');
const uuid3 = `test-form-${Math.random().toString(36).slice(2, 8)}`;
const enc3 = cookieEncrypt(uuid3, sampleData, 'pw', 'aes-128-cbc-fixed');
await upload(uuid3, enc3, 'aes-128-cbc-fixed');
const dec3 = await fetch(`${BASE}/get/${uuid3}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ password: 'pw' }).toString(),
});
const dec3Data = await dec3.json();
assert(dec3.status === 200 && JSON.stringify(dec3Data) === sampleData, 'urlencoded 请求体解析 password 成功');

console.log(`\n===== 结果: ${passed} 通过, ${failed} 失败 =====`);
process.exit(failed === 0 ? 0 : 1);
