import { createHash, createDecipheriv } from 'node:crypto';

/**
 * 与原服务端 api/app.js cookie_decrypt 完全一致的两种解密实现，
 * 用 node:crypto（Workers 原生、硬件加速）替代 crypto-js 纯 JS。
 *
 * 密钥材料: md5(uuid + '-' + password) 十六进制串的前 16 个字符。
 * 两种算法的差异仅在密钥/IV 的派生方式与密文格式。
 */

function md5Hex(s: string): string {
  return createHash('md5').update(s, 'utf8').digest('hex');
}

function md5Buf(data: Buffer): Buffer {
  return createHash('md5').update(data).digest();
}

/**
 * legacy 模式 —— 等价于 CryptoJS.AES.decrypt(encrypted, key_string)：
 *   passphrase = md5Hex(uuid+'-'+password).substring(0,16)（作为 passphrase 字符串参与派生）
 *   密文格式   = base64( "Salted__" + 8字节salt + AES-CBC 密文 )
 *
 * 注意: CryptoJS.AES 默认 keySize = 256/32 = 8 words, 所以 PasswordBasedCipher
 * 用 EVP_BytesToKey 派生 key(32) + iv(16) = 48 字节 (即 AES-256-CBC), 共 3 次 MD5 迭代:
 *   D1 = MD5(pass + salt)
 *   D2 = MD5(D1 + pass + salt)
 *   D3 = MD5(D2 + pass + salt)
 *   key = D1 || D2, iv = D3
 */
function decryptLegacy(uuid: string, encrypted: string, password: string): unknown {
  const passphrase = md5Hex(uuid + '-' + password).substring(0, 16);

  const raw = Buffer.from(encrypted, 'base64');
  if (raw.length < 16 || raw.subarray(0, 8).toString('utf8') !== 'Salted__') {
    throw new Error('Invalid legacy ciphertext: missing "Salted__" header');
  }
  const salt = raw.subarray(8, 16);
  const ciphertext = raw.subarray(16);

  const passBuf = Buffer.from(passphrase, 'utf8');
  const d1 = md5Buf(Buffer.concat([passBuf, salt]));
  const d2 = md5Buf(Buffer.concat([d1, passBuf, salt]));
  const d3 = md5Buf(Buffer.concat([d2, passBuf, salt]));
  const key = Buffer.concat([d1, d2]); // 32 字节
  const iv = d3; // 16 字节

  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted);
}

/**
 * aes-128-cbc-fixed 模式 —— 标准 AES-128-CBC：
 *   key = UTF-8 字节串 md5Hex(uuid+'-'+password).substring(0,16)
 *   iv  = 16 个零字节
 *   密文 = 不含 "Salted__" 前缀的裸 base64
 */
function decryptFixed(uuid: string, encrypted: string, password: string): unknown {
  const key = Buffer.from(md5Hex(uuid + '-' + password).substring(0, 16), 'utf8');
  const iv = Buffer.alloc(16); // 全零 IV
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64')), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted);
}

/** 解密入口，cryptoType 取值与扩展端/原服务端一致：'legacy' | 'aes-128-cbc-fixed' */
export function cookieDecrypt(uuid: string, encrypted: string, password: string, cryptoType: string = 'legacy'): unknown {
  if (cryptoType === 'aes-128-cbc-fixed') {
    return decryptFixed(uuid, encrypted, password);
  }
  return decryptLegacy(uuid, encrypted, password);
}
