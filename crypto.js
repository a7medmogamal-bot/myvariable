(function () {
  'use strict';

  const PBKDF2_ITERATIONS = 310000;
  const PBKDF2_HASH = 'SHA-256';
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const KEY_BITS = 256;
  const KEY_BYTES = 32;
  const LABEL_MASTER = 'MV-AUTH-MASTER-V1';
  const LABEL_SECOND = 'MV-AUTH-SECOND-V1';
  const SEPARATOR = '\u0000MV\u0000';

  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8');

  function assertCrypto() {
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API unavailable. Use a modern browser over HTTPS or localhost.');
    }
  }

  function assertString(v, name) {
    if (typeof v !== 'string' || v.length === 0) {
      throw new TypeError((name || 'value') + ' must be a non-empty string.');
    }
  }

  function toBytes(v) {
    if (v instanceof Uint8Array) return v;
    if (v instanceof ArrayBuffer) return new Uint8Array(v);
    if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    throw new TypeError('Expected bytes (Uint8Array / ArrayBuffer / view).');
  }

  function randomBytes(n) {
    assertCrypto();
    if (!Number.isInteger(n) || n <= 0) throw new RangeError('Invalid byte length.');
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function bufferToBase64(buf) {
    const bytes = toBytes(buf);
    let binary = '';
    const CHUNK = 8192;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      const chunk = bytes.subarray(i, Math.min(i + CHUNK, bytes.length));
      binary += String.fromCharCode.apply(null, Array.from(chunk));
    }
    return btoa(binary);
  }

  function base64ToBuffer(str) {
    assertString(str, 'base64');
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function zeroize(arr) {
    if (arr && typeof arr.fill === 'function') arr.fill(0);
  }

  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  async function deriveBits(password, salt, iterations) {
    assertCrypto();
    assertString(password, 'password');
    const s = toBytes(salt);
    const iter = iterations || PBKDF2_ITERATIONS;
    const baseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: s, iterations: iter, hash: PBKDF2_HASH },
      baseKey,
      KEY_BITS
    );
    return new Uint8Array(bits);
  }

  async function importAesKey(raw) {
    assertCrypto();
    const r = toBytes(raw);
    if (r.length !== KEY_BYTES) throw new TypeError('AES key must be 32 bytes.');
    return crypto.subtle.importKey(
      'raw',
      r,
      { name: 'AES-GCM', length: KEY_BITS },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function importHmacKey(raw) {
    assertCrypto();
    const r = toBytes(raw);
    if (r.length === 0) throw new TypeError('HMAC key must be non-empty.');
    return crypto.subtle.importKey(
      'raw',
      r,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  async function hmacSign(keyBytes, message) {
    const key = await importHmacKey(keyBytes);
    const data = typeof message === 'string' ? encoder.encode(message) : toBytes(message);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return new Uint8Array(sig);
  }

  async function buildVerifier(password, salt, label, iterations) {
    const derived = await deriveBits(password, salt, iterations);
    try {
      const mac = await hmacSign(derived, label);
      return bufferToBase64(mac);
    } finally {
      zeroize(derived);
    }
  }

  async function checkVerifier(password, salt, label, expected, iterations) {
    const computed = await buildVerifier(password, salt, label, iterations);
    return timingSafeEqual(computed, expected);
  }

  async function buildMasterVerifier(password, salt, iterations) {
    return buildVerifier(password, salt, LABEL_MASTER, iterations);
  }

  async function buildSecondVerifier(password, salt, iterations) {
    return buildVerifier(password, salt, LABEL_SECOND, iterations);
  }

  async function verifyMasterPassword(password, salt, expected, iterations) {
    return checkVerifier(password, salt, LABEL_MASTER, expected, iterations);
  }

  async function verifySecondPassword(password, salt, expected, iterations) {
    return checkVerifier(password, salt, LABEL_SECOND, expected, iterations);
  }

  async function deriveVaultKey(master, second, vaultSalt, iterations) {
    assertCrypto();
    assertString(master, 'master password');
    assertString(second, 'second password');
    const s = toBytes(vaultSalt);
    const combined = master + SEPARATOR + second;
    const raw = await deriveBits(combined, s, iterations);
    try {
      return await importAesKey(raw);
    } finally {
      zeroize(raw);
    }
  }

  async function aesEncrypt(key, plaintext) {
    assertCrypto();
    const iv = randomBytes(IV_BYTES);
    const data = typeof plaintext === 'string' ? encoder.encode(plaintext) : toBytes(plaintext);
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      data
    );
    return { iv: bufferToBase64(iv), data: bufferToBase64(cipher) };
  }

  async function aesDecrypt(key, payload) {
    assertCrypto();
    if (!payload || typeof payload.iv !== 'string' || typeof payload.data !== 'string') {
      throw new TypeError('Invalid cipher payload.');
    }
    const iv = base64ToBuffer(payload.iv);
    const cipher = base64ToBuffer(payload.data);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      cipher
    );
    return new Uint8Array(plain);
  }

  async function encryptText(key, text) {
    assertString(text, 'text');
    return aesEncrypt(key, encoder.encode(text));
  }

  async function decryptText(key, payload) {
    const bytes = await aesDecrypt(key, payload);
    return decoder.decode(bytes);
  }

  async function encryptBytes(key, bytes) {
    return aesEncrypt(key, toBytes(bytes));
  }

  async function decryptBytes(key, payload) {
    return aesDecrypt(key, payload);
  }

  async function encryptJson(key, obj) {
    return encryptText(key, JSON.stringify(obj));
  }

  async function decryptJson(key, payload) {
    const text = await decryptText(key, payload);
    return JSON.parse(text);
  }

  function generateSalts() {
    return {
      authSalt: randomBytes(SALT_BYTES),
      secondSalt: randomBytes(SALT_BYTES),
      vaultSalt: randomBytes(SALT_BYTES)
    };
  }

  function saltsToStorage(salts) {
    return {
      authSalt: bufferToBase64(salts.authSalt),
      secondSalt: bufferToBase64(salts.secondSalt),
      vaultSalt: bufferToBase64(salts.vaultSalt)
    };
  }

  function saltsFromStorage(stored) {
    if (!stored || !stored.authSalt || !stored.secondSalt || !stored.vaultSalt) return null;
    return {
      authSalt: base64ToBuffer(stored.authSalt),
      secondSalt: base64ToBuffer(stored.secondSalt),
      vaultSalt: base64ToBuffer(stored.vaultSalt)
    };
  }

  async function selfTest() {
    try {
      const salt = randomBytes(SALT_BYTES);
      const a = await deriveBits('test-password', salt, 10000);
      const b = await deriveBits('test-password', salt, 10000);
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
      const aesKey = await importAesKey(a);
      const enc = await encryptText(aesKey, 'hello world');
      const dec = await decryptText(aesKey, enc);
      if (dec !== 'hello world') return false;
      const verifier = await buildMasterVerifier('test-password', salt, 10000);
      const ok = await verifyMasterPassword('test-password', salt, verifier, 10000);
      if (!ok) return false;
      const bad = await verifyMasterPassword('wrong', salt, verifier, 10000);
      if (bad) return false;
      return true;
    } catch (e) {
      console.error('[MV.Crypto.selfTest] failed:', e);
      return false;
    }
  }

  window.MV = window.MV || {};
  window.MV.Crypto = {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    SALT_BYTES: SALT_BYTES,
    IV_BYTES: IV_BYTES,
    KEY_BYTES: KEY_BYTES,
    assertCrypto: assertCrypto,
    randomBytes: randomBytes,
    bufferToBase64: bufferToBase64,
    base64ToBuffer: base64ToBuffer,
    zeroize: zeroize,
    timingSafeEqual: timingSafeEqual,
    deriveBits: deriveBits,
    importAesKey: importAesKey,
    buildMasterVerifier: buildMasterVerifier,
    buildSecondVerifier: buildSecondVerifier,
    verifyMasterPassword: verifyMasterPassword,
    verifySecondPassword: verifySecondPassword,
    deriveVaultKey: deriveVaultKey,
    aesEncrypt: aesEncrypt,
    aesDecrypt: aesDecrypt,
    encryptText: encryptText,
    decryptText: decryptText,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,
    encryptJson: encryptJson,
    decryptJson: decryptJson,
    generateSalts: generateSalts,
    saltsToStorage: saltsToStorage,
    saltsFromStorage: saltsFromStorage,
    selfTest: selfTest
  };
})();
