(function () {
  'use strict';

  const PBKDF2_ITERATIONS = 310000;
  const PBKDF2_HASH = 'SHA-256';
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const KEY_BITS = 256;
  const KEY_BYTES = KEY_BITS / 8;
  const VERIFIER_LABEL_MASTER = 'MV-AUTH-MASTER-V1';
  const VERIFIER_LABEL_SECOND = 'MV-AUTH-SECOND-V1';
  const VAULT_SEPARATOR = '\u0000MV\u0000';

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function ensureCryptoAvailable() {
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API مش متاح. استخدم متصفح حديث أو فعّل HTTPS.');
    }
  }

  function assertString(value, name) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new TypeError((name || 'القيمة') + ' لازم تكون نص غير فارغ.');
    }
  }

  function getRandomBytes(length) {
    ensureCryptoAvailable();
    if (!Number.isInteger(length) || length <= 0) {
      throw new RangeError('طول البايتات لازم يكون رقم صحيح موجب.');
    }
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
    }
    return btoa(binary);
  }

  function base64ToBuffer(base64) {
    assertString(base64, 'Base64');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function zeroize(array) {
    if (array && typeof array.fill === 'function') {
      array.fill(0);
    }
  }

  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  async function deriveBits(password, salt, iterations) {
    ensureCryptoAvailable();
    assertString(password, 'كلمة السر');
    if (!(salt instanceof Uint8Array)) {
      throw new TypeError('الملح لازم يكون Uint8Array.');
    }
    const iter = iterations || PBKDF2_ITERATIONS;
    const baseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: iter, hash: PBKDF2_HASH },
      baseKey,
      KEY_BITS
    );
    return new Uint8Array(bits);
  }

  async function importAesKey(rawBytes) {
    ensureCryptoAvailable();
    if (!(rawBytes instanceof Uint8Array) || rawBytes.length !== KEY_BYTES) {
      throw new TypeError('مفتاح AES لازم يكون 32 بايت.');
    }
    return crypto.subtle.importKey(
      'raw',
      rawBytes,
      { name: 'AES-GCM', length: KEY_BITS },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function importHmacKey(rawBytes) {
    ensureCryptoAvailable();
    if (!(rawBytes instanceof Uint8Array) || rawBytes.length === 0) {
      throw new TypeError('مفتاح HMAC لازم يكون بايتات.');
    }
    return crypto.subtle.importKey(
      'raw',
      rawBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  async function hmacSign(rawBytes, message) {
    const key = await importHmacKey(rawBytes);
    const data = typeof message === 'string' ? encoder.encode(message) : message;
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

  async function checkVerifier(password, salt, label, expectedBase64, iterations) {
    const computed = await buildVerifier(password, salt, label, iterations);
    return timingSafeEqual(computed, expectedBase64);
  }

  async function buildMasterVerifier(password, salt, iterations) {
    return buildVerifier(password, salt, VERIFIER_LABEL_MASTER, iterations);
  }

  async function buildSecondVerifier(password, salt, iterations) {
    return buildVerifier(password, salt, VERIFIER_LABEL_SECOND, iterations);
  }

  async function verifyMasterPassword(password, salt, expectedBase64, iterations) {
    return checkVerifier(password, salt, VERIFIER_LABEL_MASTER, expectedBase64, iterations);
  }

  async function verifySecondPassword(password, salt, expectedBase64, iterations) {
    return checkVerifier(password, salt, VERIFIER_LABEL_SECOND, expectedBase64, iterations);
  }

  async function deriveVaultKey(masterPassword, secondPassword, vaultSalt, iterations) {
    ensureCryptoAvailable();
    assertString(masterPassword, 'كلمة السر الرئيسية');
    assertString(secondPassword, 'كلمة السر الثانية');
    if (!(vaultSalt instanceof Uint8Array)) {
      throw new TypeError('ملح الخزنة لازم يكون Uint8Array.');
    }
    const combined = masterPassword + VAULT_SEPARATOR + secondPassword;
    const raw = await deriveBits(combined, vaultSalt, iterations);
    try {
      return await importAesKey(raw);
    } finally {
      zeroize(raw);
    }
  }

  async function aesEncrypt(aesKey, plaintext) {
    ensureCryptoAvailable();
    const iv = getRandomBytes(IV_BYTES);
    const data = typeof plaintext === 'string' ? encoder.encode(plaintext) : plaintext;
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      aesKey,
      data
    );
    return {
      iv: bufferToBase64(iv),
      data: bufferToBase64(cipher)
    };
  }

  async function aesDecrypt(aesKey, payload) {
    ensureCryptoAvailable();
    if (!payload || typeof payload.iv !== 'string' || typeof payload.data !== 'string') {
      throw new TypeError('حمولة التشفير غير صالحة.');
    }
    const iv = base64ToBuffer(payload.iv);
    const cipher = base64ToBuffer(payload.data);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      aesKey,
      cipher
    );
    return new Uint8Array(plain);
  }

  async function encryptText(aesKey, text) {
    assertString(text, 'النص');
    return aesEncrypt(aesKey, encoder.encode(text));
  }

  async function decryptText(aesKey, payload) {
    const bytes = await aesDecrypt(aesKey, payload);
    return decoder.decode(bytes);
  }

  async function encryptBytes(aesKey, bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('البيانات لازم تكون Uint8Array.');
    }
    return aesEncrypt(aesKey, bytes);
  }

  async function decryptBytes(aesKey, payload) {
    return aesDecrypt(aesKey, payload);
  }

  async function encryptJson(aesKey, obj) {
    return encryptText(aesKey, JSON.stringify(obj));
  }

  async function decryptJson(aesKey, payload) {
    const text = await decryptText(aesKey, payload);
    return JSON.parse(text);
  }

  function generateSalts() {
    return {
      authSalt: getRandomBytes(SALT_BYTES),
      secondSalt: getRandomBytes(SALT_BYTES),
      vaultSalt: getRandomBytes(SALT_BYTES)
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

  window.MV = window.MV || {};
  window.MV.Crypto = {
    PBKDF2_ITERATIONS,
    SALT_BYTES,
    IV_BYTES,
    KEY_BYTES,
    ensureCryptoAvailable,
    getRandomBytes,
    bufferToBase64,
    base64ToBuffer,
    zeroize,
    timingSafeEqual,
    deriveBits,
    importAesKey,
    buildMasterVerifier,
    buildSecondVerifier,
    verifyMasterPassword,
    verifySecondPassword,
    deriveVaultKey,
    aesEncrypt,
    aesDecrypt,
    encryptText,
    decryptText,
    encryptBytes,
    decryptBytes,
    encryptJson,
    decryptJson,
    generateSalts,
    saltsToStorage,
    saltsFromStorage
  };
})();
