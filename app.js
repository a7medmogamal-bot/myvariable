(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  const $$ = s => Array.from(document.querySelectorAll(s));
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 10); }
  function fmtBytes(b) { if (!b) return '0 B'; const u = ['B', 'KB', 'MB', 'GB']; const i = Math.floor(Math.log(b) / Math.log(1024)); return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i]; }
  function fmtDate(ts) { try { return new Date(ts).toLocaleString('ar-EG'); } catch (e) { return ''; } }

  const Crypto = (() => {
    const ITER = 310000, KEY_BYTES = 32, IV_BYTES = 12, SALT_BYTES = 16;
    const SEP = '\u0000MV\u0000';
    const LM = 'MV-AUTH-MASTER-V1', LS = 'MV-AUTH-SECOND-V1';

    function rb(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
    function b64(buf) { const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf); let s = ''; const C = 0x8000; for (let i = 0; i < a.length; i += C) s += String.fromCharCode.apply(null, Array.from(a.subarray(i, Math.min(i + C, a.length)))); return btoa(s); }
    function unb64(str) { const bin = atob(str); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
    function z(a) { if (a && a.fill) a.fill(0); }
    function tseq(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }

    async function pbkdf2(pwd, salt, iter) {
      const base = await crypto.subtle.importKey('raw', ENC.encode(pwd), { name: 'PBKDF2' }, false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: iter || ITER, hash: 'SHA-256' }, base, 256);
      return new Uint8Array(bits);
    }
    async function importAes(raw) { return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); }

    async function verifier(pwd, salt, label, iter) {
      const d = await pbkdf2(pwd, salt, iter);
      try {
        const k = await crypto.subtle.importKey('raw', d, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', k, ENC.encode(label));
        return b64(new Uint8Array(sig));
      } finally { z(d); }
    }
    async function deriveWrap(m, s, salt, iter) {
      const raw = await pbkdf2(m + SEP + s, salt, iter);
      try { return await importAes(raw); } finally { z(raw); }
    }
    async function aesEnc(key, data) {
      const iv = rb(IV_BYTES);
      const buf = typeof data === 'string' ? ENC.encode(data) : (data instanceof Uint8Array ? data : new Uint8Array(data));
      const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, buf);
      return { iv: b64(iv), data: b64(new Uint8Array(c)) };
    }
    async function aesDec(key, p) {
      const iv = unb64(p.iv), c = unb64(p.data);
      const p2 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, c);
      return new Uint8Array(p2);
    }
    async function encJson(key, obj) { return aesEnc(key, JSON.stringify(obj)); }
    async function decJson(key, p) { return JSON.parse(DEC.decode(await aesDec(key, p))); }

    async function selfTest() {
      try {
        const salt = rb(SALT_BYTES);
        const a = await pbkdf2('t', salt, 1000), b = await pbkdf2('t', salt, 1000);
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        const k = await importAes(a);
        const e = await aesEnc(k, 'hi');
        if (DEC.decode(await aesDec(k, e)) !== 'hi') return false;
        const v1 = await verifier('t', salt, LM, 1000), v2 = await verifier('t', salt, LM, 1000);
        return tseq(v1, v2);
      } catch (e) { console.warn('[MV] selfTest error', e); return false; }
    }

    return { rb, b64, unb64, z, tseq, pbkdf2, importAes, verifier, deriveWrap, aesEnc, aesDec, encJson, decJson, selfTest, ITER, SALT_BYTES, IV_BYTES, KEY_BYTES, LM, LS };
  })();

  const DB = (() => {
    const NAME = 'my-variable-db', VER = 1;
    let db = null;
    async function init() {
      return new Promise((res, rej) => {
        const r = indexedDB.open(NAME, VER);
        r.onerror = () => rej(r.error);
        r.onupgradeneeded = e => {
          const d = e.target.result;
          if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta', { keyPath: 'key' });
          if (!d.objectStoreNames.contains('cards')) d.createObjectStore('cards', { keyPath: 'id' });
          if (!d.objectStoreNames.contains('images')) {
            const s = d.createObjectStore('images', { keyPath: 'id' });
            s.createIndex('cardId', 'cardId', { unique: false });
          }
          if (!d.objectStoreNames.contains('categories')) d.createObjectStore('categories', { keyPath: 'id' });
        };
        r.onsuccess = () => { db = r.result; res(db); };
      });
    }
    function s(name, mode) { return db.transaction(name, mode).objectStore(name); }
    function p(req) { return new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); }); }

    const mGet = k => p(s('meta', 'readonly').get(k));
    const mPut = v => p(s('meta', 'readwrite').put(v));
    const mDel = k => p(s('meta', 'readwrite').delete(k));
    const cPut = v => p(s('cards', 'readwrite').put(v));
    const cGet = k => p(s('cards', 'readonly').get(k));
    const cDel = k => p(s('cards', 'readwrite').delete(k));
    const cAll = () => p(s('cards', 'readonly').getAll());
    const iPut = v => p(s('images', 'readwrite').put(v));
    const iGet = k => p(s('images', 'readonly').get(k));
    const iDel = k => p(s('images', 'readwrite').delete(k));
    const iByCard = cid => p(s('images', 'readonly').index('cardId').getAll(cid));
    const iAll = () => p(s('images', 'readonly').getAll());
    const catPut = v => p(s('categories', 'readwrite').put(v));
    const catGet = k => p(s('categories', 'readonly').get(k));
    const catDel = k => p(s('categories', 'readwrite').delete(k));
    const catAll = () => p(s('categories', 'readonly').getAll());

    async function clearAll() {
      await p(s('meta', 'readwrite').clear());
      await p(s('cards', 'readwrite').clear());
      await p(s('images', 'readwrite').clear());
      await p(s('categories', 'readwrite').clear());
    }
    async function stats() {
      const [c, i, ca] = await Promise.all([cAll(), iAll(), catAll()]);
      return { cards: c.length, images: i.length, categories: ca.length };
    }
    return { init, clearAll, stats, getMeta: mGet, setMeta: mPut, deleteMeta: mDel, putCard: cPut, getCard: cGet, deleteCard: cDel, getAllCards: cAll, putImage: iPut, getImage: iGet, deleteImage: iDel, getImagesByCard: iByCard, getAllImages: iAll, putCategory: catPut, getCategory: catGet, deleteCategory: catDel, getAllCategories: catAll };
  })();

  const Auth = (() => {
    const VER = 2;
    let vaultKey = null, unlocked = false;
    const lockCbs = [];
    const failures = { master: 0, second: 0 };

    function delayFor(k) { const f = failures[k]; if (f < 5) return 0; return Math.min(60000, 3000 * Math.pow(2, f - 5)); }
    async function loadRec() { const r = await DB.getMeta('auth'); return r ? r.value : null; }
    async function saveRec(v) { await DB.setMeta({ key: 'auth', value: v }); }
    function valid(r) { return r && r.version === VER && r.authSalt && r.secondSalt && r.wrapSalt && r.masterVerifier && r.secondVerifier && r.wrappedKey && r.iterations; }

    async function hasSetup() { return valid(await loadRec()); }
    async function setup(m, s) {
      if (await hasSetup()) throw new Error('already initialized');
      const aS = Crypto.rb(16), sS = Crypto.rb(16), wS = Crypto.rb(16);
      const mV = await Crypto.verifier(m, aS, Crypto.LM, Crypto.ITER);
      const sV = await Crypto.verifier(s, sS, Crypto.LS, Crypto.ITER);
      const wK = await Crypto.deriveWrap(m, s, wS, Crypto.ITER);
      const vkB = Crypto.rb(32);
      const wrappedKey = await Crypto.aesEnc(wK, vkB);
      Crypto.z(vkB);
      await saveRec({ version: VER, iterations: Crypto.ITER, authSalt: Crypto.b64(aS), secondSalt: Crypto.b64(sS), wrapSalt: Crypto.b64(wS), masterVerifier: mV, secondVerifier: sV, wrappedKey, createdAt: Date.now(), updatedAt: Date.now() });
    }
    async function verifyMaster(pw) {
      if (!pw) return false;
      const d = delayFor('master'); if (d) await new Promise(r => setTimeout(r, d));
      const rec = await loadRec(); if (!valid(rec)) return false;
      try {
        const ok = Crypto.tseq(await Crypto.verifier(pw, Crypto.unb64(rec.authSalt), Crypto.LM, rec.iterations), rec.masterVerifier);
        ok ? failures.master = 0 : failures.master++;
        return ok;
      } catch (e) { failures.master++; return false; }
    }
    async function verifySecond(pw) {
      if (!pw) return false;
      const d = delayFor('second'); if (d) await new Promise(r => setTimeout(r, d));
      const rec = await loadRec(); if (!valid(rec)) return false;
      try {
        const ok = Crypto.tseq(await Crypto.verifier(pw, Crypto.unb64(rec.secondSalt), Crypto.LS, rec.iterations), rec.secondVerifier);
        ok ? failures.second = 0 : failures.second++;
        return ok;
      } catch (e) { failures.second++; return false; }
    }
    async function completeLogin(m, s) {
      const rec = await loadRec(); if (!valid(rec)) throw new Error('not initialized');
      const wK = await Crypto.deriveWrap(m, s, Crypto.unb64(rec.wrapSalt), rec.iterations);
      let vkB;
      try { vkB = await Crypto.aesDec(wK, rec.wrappedKey); }
      catch (e) { throw new Error('bad credentials'); }
      try { vaultKey = await Crypto.importAes(vkB); unlocked = true; failures.master = 0; failures.second = 0; }
      finally { Crypto.z(vkB); }
    }
    function getVaultKey() { if (!vaultKey) throw new Error('locked'); return vaultKey; }
    function isUnlocked() { return unlocked && !!vaultKey; }
    function lock() { vaultKey = null; unlocked = false; lockCbs.forEach(cb => { try { cb(); } catch (e) { } }); }
    function onLock(cb) { if (typeof cb === 'function') lockCbs.push(cb); }

    async function changeMaster(cm, cs, nm) {
      if (!nm || nm === cm) throw new Error('invalid new password');
      if (!await verifyMaster(cm)) throw new Error('current master wrong');
      if (!await verifySecond(cs)) throw new Error('current second wrong');
      const rec = await loadRec(); if (!valid(rec)) throw new Error('not init');
      const wK = await Crypto.deriveWrap(cm, cs, Crypto.unb64(rec.wrapSalt), rec.iterations);
      const vkB = await Crypto.aesDec(wK, rec.wrappedKey);
      try {
        const na = Crypto.rb(16), nw = Crypto.rb(16);
        const nv = await Crypto.verifier(nm, na, Crypto.LM, rec.iterations);
        const nwk = await Crypto.deriveWrap(nm, cs, nw, rec.iterations);
        const nww = await Crypto.aesEnc(nwk, vkB);
        await saveRec(Object.assign({}, rec, { authSalt: Crypto.b64(na), wrapSalt: Crypto.b64(nw), masterVerifier: nv, wrappedKey: nww, updatedAt: Date.now() }));
        if (unlocked) vaultKey = await Crypto.importAes(vkB);
      } finally { Crypto.z(vkB); }
    }
    async function changeSecond(cm, cs, ns) {
      if (!ns || ns === cs) throw new Error('invalid new password');
      if (!await verifyMaster(cm)) throw new Error('current master wrong');
      if (!await verifySecond(cs)) throw new Error('current second wrong');
      const rec = await loadRec(); if (!valid(rec)) throw new Error('not init');
      const wK = await Crypto.deriveWrap(cm, cs, Crypto.unb64(rec.wrapSalt), rec.iterations);
      const vkB = await Crypto.aesDec(wK, rec.wrappedKey);
      try {
        const nsalt = Crypto.rb(16), nw = Crypto.rb(16);
        const nv = await Crypto.verifier(ns, nsalt, Crypto.LS, rec.iterations);
        const nwk = await Crypto.deriveWrap(cm, ns, nw, rec.iterations);
        const nww = await Crypto.aesEnc(nwk, vkB);
        await saveRec(Object.assign({}, rec, { secondSalt: Crypto.b64(nsalt), wrapSalt: Crypto.b64(nw), secondVerifier: nv, wrappedKey: nww, updatedAt: Date.now() }));
        if (unlocked) vaultKey = await Crypto.importAes(vkB);
      } finally { Crypto.z(vkB); }
    }
    async function init() { return hasSetup(); }
    async function reset() { try { await DB.deleteMeta('auth'); } catch (e) { } vaultKey = null; unlocked = false; }

    return { init, hasSetup, setup, verifyMaster, verifySecond, completeLogin, getVaultKey, isUnlocked, lock, onLock, changeMasterPassword: changeMaster, changeSecondPassword: changeSecond, reset };
  })();

  const Images = (() => {
    const urlCache = new Map();
    async function compress(file) {
      return new Promise((res, rej) => {
        const img = new Image();
        const url = URL.createObjectURL(file);
        img.onload = () => {
          URL.revokeObjectURL(url);
          let w = img.naturalWidth, h = img.naturalHeight;
          const max = 1600;
          if (w > max || h > max) { if (w > h) { h = Math.round(h * max / w); w = max; } else { w = Math.round(w * max / h); h = max; } }
          const cv = document.createElement('canvas');
          cv.width = w; cv.height = h;
          cv.getContext('2d').drawImage(img, 0, 0, w, h);
          cv.toBlob(b => b ? res(b) : rej(new Error('toBlob failed')), 'image/jpeg', 0.85);
        };
        img.onerror = () => { URL.revokeObjectURL(url); rej(new Error('img load failed')); };
        img.src = url;
      });
    }
    async function addFiles(cardId, files) {
      const ids = [];
      for (const f of files) {
        if (!f.type.startsWith('image/')) continue;
        try {
          const comp = await compress(f);
          const buf = new Uint8Array(await comp.arrayBuffer());
          const e = await Crypto.aesEnc(Auth.getVaultKey(), buf);
          const id = uid();
          await DB.putImage({ id, cardId, iv: e.iv, data: e.data, mime: 'image/jpeg', size: comp.size, createdAt: Date.now() });
          ids.push(id);
        } catch (e) { console.error('add file failed', e); }
      }
      return ids;
    }
    async function getUrl(id) {
      if (urlCache.has(id)) return urlCache.get(id);
      const rec = await DB.getImage(id); if (!rec) return null;
      try {
        const bytes = await Crypto.aesDec(Auth.getVaultKey(), { iv: rec.iv, data: rec.data });
        const url = URL.createObjectURL(new Blob([bytes], { type: rec.mime || 'image/jpeg' }));
        urlCache.set(id, url);
        return url;
      } catch (e) { console.error('dec img failed', e); return null; }
    }
    async function remove(id) { if (urlCache.has(id)) { URL.revokeObjectURL(urlCache.get(id)); urlCache.delete(id); } await DB.deleteImage(id); }
    async function removeByCard(cid) { const rs = await DB.getImagesByCard(cid); for (const r of rs) await remove(r.id); }
    function clearCache() { for (const u of urlCache.values()) URL.revokeObjectURL(u); urlCache.clear(); }
    return { addFiles, getUrl, remove, removeByCard, clearCache };
  })();

  const Cards = (() => {
    const cache = new Map();
    const categoriesCache = new Map();
    let editBuffer = null;
    const lastEditImages = new Set();
    const defaultCategories = [
      { id: 'gaming', name: 'Gaming', icon: 'icon-star' },
      { id: 'social', name: 'Social Media', icon: 'icon-user' },
      { id: 'email', name: 'Email', icon: 'icon-mail' },
      { id: 'work', name: 'Work', icon: 'icon-id' },
      { id: 'personal', name: 'Personal', icon: 'icon-user' },
      { id: 'websites', name: 'Websites', icon: 'icon-link' },
      { id: 'other', name: 'Other', icon: 'icon-folder' }
    ];
    async function loadCategories() {
      categoriesCache.clear();
      const recs = await DB.getAllCategories();
      if (!recs.length) { for (const dc of defaultCategories) { await DB.putCategory(Object.assign({}, dc, { isDefault: true })); categoriesCache.set(dc.id, dc); } }
      else for (const r of recs) categoriesCache.set(r.id, r);
    }
    function getCategories() { return Array.from(categoriesCache.values()); }
    function getCategory(id) { return categoriesCache.get(id) || { id, name: 'قسم', icon: 'icon-folder' }; }
    async function loadAll() {
      cache.clear();
      const recs = await DB.getAllCards();
      for (const r of recs) {
        try {
          const obj = await Crypto.decJson(Auth.getVaultKey(), r.payload);
          obj.id = r.id; obj.favorite = r.favorite; obj.createdAt = r.createdAt; obj.updatedAt = r.updatedAt;
          cache.set(r.id, obj);
        } catch (e) { console.error('dec card failed', r.id, e); }
      }
    }
    function getAll() { return Array.from(cache.values()); }
    function getById(id) { return cache.get(id); }
    function filtered() {
      let list = getAll();
      if (App.state.searchQuery) {
        const q = App.state.searchQuery.toLowerCase();
        list = list.filter(c => (c.name || '').toLowerCase().includes(q) || (c.description || '').toLowerCase().includes(q) || (c.username || '').toLowerCase().includes(q) || (c.email || '').toLowerCase().includes(q));
      }
      if (App.state.activeCategory !== 'all') list = list.filter(c => c.categoryId === App.state.activeCategory);
      const m = App.state.sortMode;
      if (m === 'name') list.sort((a, b) => (a.name || '').localeCompare(b.name || '', 'ar'));
      else if (m === 'created') list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      else list.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      return list;
    }
    function cardEl(card) {
      const cat = getCategory(card.categoryId);
      const el = document.createElement('div');
      el.className = 'card-item'; el.dataset.id = card.id;
      el.innerHTML = '<div class="card-item__cover">' +
        (card.coverImageId ? '<img alt="" data-cover="' + esc(card.coverImageId) + '">' : '<svg class="icon icon--xl card-item__cover-fallback"><use href="#icon-image"></use></svg>') +
        (card.favorite ? '<span class="card-item__fav"><svg class="icon icon--solid"><use href="#icon-star-filled"></use></svg></span>' : '') +
        '</div><div class="card-item__body"><div class="card-item__name">' + esc(card.name || 'بدون اسم') + '</div>' +
        '<div class="card-item__category"><span class="card-item__category-dot"></span><span>' + esc(cat.name) + '</span></div></div>';
      el.addEventListener('click', () => App.openDetails(card.id));
      return el;
    }
    async function hydrate(el, imgId) { const url = await Images.getUrl(imgId); if (url) { const im = el.querySelector('img[data-cover]'); if (im) im.src = url; } }
    function renderDashboard() {
      const list = filtered();
      const grid = $('cards-grid'), empty = $('dashboard-empty'), cnt = $('cards-count');
      if (!grid) return;
      grid.innerHTML = '';
      if (cnt) cnt.textContent = String(list.length);
      if (!list.length) { if (empty) empty.hidden = false; }
      else {
        if (empty) empty.hidden = true;
        for (const c of list) { const el = cardEl(c); grid.appendChild(el); if (c.coverImageId) hydrate(el, c.coverImageId); }
      }
      renderFavoritesRow();
    }
    function renderFavoritesRow() {
      const favs = getAll().filter(c => c.favorite).slice(0, 8);
      const sec = $('favorites-section'), row = $('favorites-row'), cnt = $('favorites-count');
      if (!sec || !row) return;
      if (cnt) cnt.textContent = String(favs.length);
      if (!favs.length) { sec.hidden = true; return; }
      sec.hidden = false; row.innerHTML = '';
      for (const c of favs) { const el = cardEl(c); row.appendChild(el); if (c.coverImageId) hydrate(el, c.coverImageId); }
    }
    function renderFavoritesPage() {
      const favs = getAll().filter(c => c.favorite);
      const m = App.state.sortMode;
      if (m === 'name') favs.sort((a, b) => (a.name || '').localeCompare(b.name || '', 'ar'));
      else if (m === 'created') favs.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      else favs.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      const grid = $('favorites-grid'), empty = $('favorites-empty'), cnt = $('favorites-page-count');
      if (!grid) return;
      if (cnt) cnt.textContent = String(favs.length);
      grid.innerHTML = '';
      if (!favs.length) { if (empty) empty.hidden = false; }
      else { if (empty) empty.hidden = true; for (const c of favs) { const el = cardEl(c); grid.appendChild(el); if (c.coverImageId) hydrate(el, c.coverImageId); } }
    }
    function renderChips() {
      const chips = $('category-chips'); if (!chips) return;
      chips.innerHTML = '';
      const all = document.createElement('button');
      all.className = 'chip' + (App.state.activeCategory === 'all' ? ' is-active' : '');
      all.textContent = 'الكل';
      all.addEventListener('click', () => { App.state.activeCategory = 'all'; renderChips(); renderDashboard(); });
      chips.appendChild(all);
      for (const cat of getCategories()) {
        const ch = document.createElement('button');
        ch.className = 'chip' + (App.state.activeCategory === cat.id ? ' is-active' : '');
        ch.textContent = cat.name;
        ch.addEventListener('click', () => { App.state.activeCategory = cat.id; renderChips(); renderDashboard(); });
        chips.appendChild(ch);
      }
    }
    function renderCategoriesPage() {
      const list = $('categories-list'), empty = $('categories-empty');
      if (!list) return;
      list.innerHTML = '';
      const cats = getCategories();
      if (!cats.length) { if (empty) empty.hidden = false; return; }
      if (empty) empty.hidden = true;
      const counts = new Map();
      for (const c of getAll()) counts.set(c.categoryId, (counts.get(c.categoryId) || 0) + 1);
      for (const cat of cats) {
        const it = document.createElement('div');
        it.className = 'category-item';
        it.innerHTML = '<div class="category-item__icon"><svg class="icon"><use href="#' + (cat.icon || 'icon-folder') + '"></use></svg></div>' +
          '<div class="category-item__body"><div class="category-item__name">' + esc(cat.name) + '</div>' +
          '<div class="category-item__count">' + (counts.get(cat.id) || 0) + ' كارت</div></div>' +
          '<div class="category-item__actions">' + (!cat.isDefault ? '<button type="button" class="icon-btn icon-btn--danger" data-act="del"><svg class="icon icon--sm"><use href="#icon-trash"></use></svg></button>' : '') + '</div>';
        const del = it.querySelector('[data-act="del"]');
        if (del) del.addEventListener('click', async () => {
          const ok = await App.confirm({ title: 'حذف القسم', text: 'تحذف قسم "' + cat.name + '"؟ الكروت هتتنقل لقسم Other.', confirmText: 'احذف', danger: true });
          if (!ok) return;
          const affected = getAll().filter(c => c.categoryId === cat.id);
          for (const c of affected) { c.categoryId = 'other'; c.updatedAt = Date.now(); await DB.putCard({ id: c.id, favorite: c.favorite, createdAt: c.createdAt, updatedAt: c.updatedAt, payload: await Crypto.encJson(Auth.getVaultKey(), c) }); }
          await DB.deleteCategory(cat.id);
          categoriesCache.delete(cat.id);
          App.toast('تم حذف القسم', 'success');
          renderCategoriesPage(); renderChips(); renderDashboard();
        });
        list.appendChild(it);
      }
    }
    async function addCategory() {
      const name = prompt('اسم القسم الجديد:');
      if (!name || !name.trim()) return;
      const id = uid();
      await DB.putCategory({ id, name: name.trim(), icon: 'icon-folder', isDefault: false });
      categoriesCache.set(id, { id, name: name.trim(), icon: 'icon-folder' });
      App.toast('تم إضافة القسم', 'success');
      renderCategoriesPage(); renderChips();
    }
    async function toggleFavorite(id) {
      const card = cache.get(id); if (!card) return;
      card.favorite = !card.favorite; card.updatedAt = Date.now();
      await DB.putCard({ id: card.id, favorite: card.favorite, createdAt: card.createdAt, updatedAt: card.updatedAt, payload: await Crypto.encJson(Auth.getVaultKey(), card) });
      App.toast(card.favorite ? 'أضيف للمفضلة' : 'اتشال من المفضلة', 'success');
      renderDashboard(); renderFavoritesPage();
      if (App.state.view === 'details' && App.state.currentCardId === id) renderDetails(id);
    }
    async function deleteCard(id) { await Images.removeByCard(id); await DB.deleteCard(id); cache.delete(id); }
    function fieldEl(label, value, icon, canCopy, sensitive) {
      const div = document.createElement('div');
      div.className = 'data-field';
      const isMasked = !!sensitive;
      const display = isMasked ? '••••••••' : value;
      div.innerHTML = '<div class="data-field__icon"><svg class="icon"><use href="#' + (icon || 'icon-note') + '"></use></svg></div>' +
        '<div class="data-field__body"><div class="data-field__label">' + esc(label) + '</div>' +
        '<div class="data-field__value ' + (isMasked ? 'data-field__value--masked' : '') + '"></div></div>' +
        '<div class="data-field__actions">' +
        (isMasked ? '<button type="button" class="icon-btn" data-act="toggle"><svg class="icon icon--sm"><use href="#icon-eye"></use></svg></button>' : '') +
        (canCopy ? '<button type="button" class="icon-btn" data-act="copy"><svg class="icon icon--sm"><use href="#icon-copy"></use></svg></button>' : '') +
        '</div>';
      const valEl = div.querySelector('.data-field__value');
      valEl.textContent = display;
      if (isMasked) {
        let shown = false, tm = null;
        const btn = div.querySelector('[data-act="toggle"]');
        btn.addEventListener('click', () => {
          shown = !shown;
          valEl.textContent = shown ? value : '••••••••';
          valEl.classList.toggle('data-field__value--masked', !shown);
          btn.querySelector('use').setAttribute('href', shown ? '#icon-eye-off' : '#icon-eye');
          if (tm) clearTimeout(tm);
          if (shown) { const s = App.readSetting('visibility', 15); tm = setTimeout(() => { shown = false; valEl.textContent = '••••••••'; valEl.classList.add('data-field__value--masked'); btn.querySelector('use').setAttribute('href', '#icon-eye'); }, s * 1000); }
        });
      }
      if (canCopy) div.querySelector('[data-act="copy"]').addEventListener('click', () => App.copy(value, sensitive));
      return div;
    }
    async function renderDetails(id) {
      const card = cache.get(id);
      if (!card) { App.toast('الكارت مش موجود', 'error'); return; }
      App.state.currentCardId = id;
      const cover = $('details-cover');
      if (cover) {
        cover.innerHTML = '';
        if (card.coverImageId) {
          const url = await Images.getUrl(card.coverImageId);
          if (url) { const im = document.createElement('img'); im.src = url; cover.appendChild(im); }
          else cover.innerHTML = '<div class="details__cover-fallback"><svg class="icon icon--xl"><use href="#icon-image"></use></svg></div>';
        } else cover.innerHTML = '<div class="details__cover-fallback"><svg class="icon icon--xl"><use href="#icon-image"></use></svg></div>';
      }
      $('details-name').textContent = card.name || 'بدون اسم';
      $('details-category').textContent = getCategory(card.categoryId).name;
      $('details-fav-badge').hidden = !card.favorite;
      const desc = $('details-description');
      if (card.description) { desc.textContent = card.description; desc.hidden = false; } else desc.hidden = true;
      const favBtn = $('btn-details-favorite');
      if (favBtn) { favBtn.setAttribute('aria-pressed', card.favorite ? 'true' : 'false'); favBtn.querySelector('use').setAttribute('href', card.favorite ? '#icon-star-filled' : '#icon-star'); }
      const gallery = $('details-gallery'), gsec = $('details-gallery-section');
      if (gallery && gsec) {
        gallery.innerHTML = '';
        if (card.imageIds && card.imageIds.length) {
          gsec.hidden = false;
          card.imageIds.forEach((imgId, i) => {
            const it = document.createElement('div'); it.className = 'gallery__item'; it.innerHTML = '<img alt="">';
            gallery.appendChild(it);
            Images.getUrl(imgId).then(u => { if (u) it.querySelector('img').src = u; });
            it.addEventListener('click', () => App.openViewer(card.imageIds, i));
          });
        } else gsec.hidden = true;
      }
      const fields = $('details-fields');
      if (fields) {
        fields.innerHTML = '';
        [['username', 'اسم المستخدم', 'icon-user', true, false], ['password', 'كلمة السر', 'icon-lock', true, true], ['email', 'البريد', 'icon-mail', true, false], ['phone', 'الهاتف', 'icon-phone', true, false], ['accountId', 'معرّف الحساب', 'icon-id', true, false], ['recoveryEmail', 'بريد الاستعادة', 'icon-mail', true, false], ['notes', 'ملاحظات', 'icon-note', false, false]].forEach(function (a) { if (card[a[0]]) fields.appendChild(fieldEl(a[1], card[a[0]], a[2], a[3], a[4])); });
      }
      const cfs = $('details-custom-fields'), cfsec = $('details-custom-section');
      if (cfs && cfsec) {
        cfs.innerHTML = '';
        if (card.customFields && card.customFields.length) { cfsec.hidden = false; card.customFields.forEach(f => { if (f.value) cfs.appendChild(fieldEl(f.label || 'حقل', f.value, 'icon-note', true, false)); }); }
        else cfsec.hidden = true;
      }
      const links = $('details-links'), lsec = $('details-links-section');
      if (links && lsec) {
        links.innerHTML = '';
        if (card.links && card.links.length) {
          lsec.hidden = false;
          card.links.forEach(l => {
            const a = document.createElement('a');
            a.className = 'link-item'; a.href = l.url || '#'; a.target = '_blank'; a.rel = 'noopener noreferrer';
            a.innerHTML = '<div class="link-item__icon"><svg class="icon"><use href="#icon-link"></use></svg></div>' +
              '<div class="link-item__body"><div class="link-item__title">' + esc(l.title || l.url) + '</div>' +
              '<div class="link-item__url">' + esc(l.url) + '</div>' +
              (l.description ? '<div class="link-item__desc">' + esc(l.description) + '</div>' : '') + '</div>';
            links.appendChild(a);
          });
        } else lsec.hidden = true;
      }
      const dates = $('details-dates');
      if (dates) dates.innerHTML = '<span>تم الإنشاء: <strong>' + fmtDate(card.createdAt) + '</strong></span><span>آخر تعديل: <strong>' + fmtDate(card.updatedAt) + '</strong></span>';
    }
    async function openEditor(cardId) {
      const form = $('card-form'); if (form) form.reset();
      $('custom-fields-list').innerHTML = '';
      $('links-list').innerHTML = '';
      $('editor-images').innerHTML = '';
      $('editor-cover-preview').innerHTML = '<svg class="icon icon--xl"><use href="#icon-image"></use></svg>';
      $('editor-name-error').classList.remove('is-visible');
      $('editor-name-error').textContent = '';
      const catSel = $('editor-category');
      if (catSel) { catSel.innerHTML = ''; for (const c of getCategories()) { const o = document.createElement('option'); o.value = c.id; o.textContent = c.name; catSel.appendChild(o); } }
      lastEditImages.clear();
      if (cardId) {
        const card = cache.get(cardId);
        if (!card) { App.toast('مش موجود', 'error'); return; }
        editBuffer = JSON.parse(JSON.stringify(card));
        $('editor-name').value = card.name || '';
        $('editor-category').value = card.categoryId || 'other';
        $('editor-description').value = card.description || '';
        $('editor-username').value = card.username || '';
        $('editor-password').value = card.password || '';
        $('editor-email').value = card.email || '';
        $('editor-phone').value = card.phone || '';
        $('editor-account-id').value = card.accountId || '';
        $('editor-recovery-email').value = card.recoveryEmail || '';
        $('editor-notes').value = card.notes || '';
        for (const f of card.customFields || []) addCustomFieldRow(f);
        for (const l of card.links || []) addLinkRow(l);
        if (card.coverImageId) Images.getUrl(card.coverImageId).then(u => { if (u) $('editor-cover-preview').innerHTML = '<img src="' + u + '" alt="">'; });
        for (const imgId of card.imageIds || []) { await addEditorImageThumb(imgId, card.coverImageId === imgId); lastEditImages.add(imgId); }
      } else {
        editBuffer = { id: null, name: '', categoryId: 'other', description: '', coverImageId: null, username: '', password: '', email: '', phone: '', accountId: '', recoveryEmail: '', notes: '', customFields: [], links: [], imageIds: [], favorite: false, createdAt: Date.now(), updatedAt: Date.now() };
        $('editor-category').value = 'other';
      }
    }
    function addCustomFieldRow(data) {
      const list = $('custom-fields-list'); if (!list) return;
      const row = document.createElement('div');
      row.className = 'custom-field'; row.dataset.id = data.id || uid();
      row.innerHTML = '<div class="custom-field__row"><div class="field__control"><input class="field__input" type="text" placeholder="اسم الحقل" data-role="label" value="' + esc(data.label || '') + '"></div>' +
        '<button type="button" class="custom-field__remove icon-btn icon-btn--danger"><svg class="icon icon--sm"><use href="#icon-trash"></use></svg></button></div>' +
        '<div class="field__control"><input class="field__input" type="text" placeholder="القيمة" data-role="value" value="' + esc(data.value || '') + '"></div>';
      list.appendChild(row);
      row.querySelector('.custom-field__remove').addEventListener('click', () => row.remove());
    }
    function addLinkRow(data) {
      const list = $('links-list'); if (!list) return;
      const row = document.createElement('div');
      row.className = 'link-editor'; row.dataset.id = data.id || uid();
      row.innerHTML = '<div class="link-editor__row"><div class="field__control"><input class="field__input" type="text" placeholder="العنوان" data-role="title" value="' + esc(data.title || '') + '"></div>' +
        '<button type="button" class="link-editor__remove icon-btn icon-btn--danger"><svg class="icon icon--sm"><use href="#icon-trash"></use></svg></button></div>' +
        '<div class="field__control"><input class="field__input" type="url" placeholder="https://..." data-role="url" value="' + esc(data.url || '') + '"></div>' +
        '<div class="field__control"><input class="field__input" type="text" placeholder="وصف" data-role="description" value="' + esc(data.description || '') + '"></div>';
      list.appendChild(row);
      row.querySelector('.link-editor__remove').addEventListener('click', () => row.remove());
    }
    async function addEditorImageThumb(imgId, isCover) {
      const list = $('editor-images'); if (!list) return;
      const url = await Images.getUrl(imgId); if (!url) return;
      const div = document.createElement('div');
      div.className = 'editor-image' + (isCover ? ' is-cover' : '');
      div.dataset.id = imgId;
      div.innerHTML = '<img src="' + url + '" alt="">' + (isCover ? '<span class="editor-image__badge">غلاف</span>' : '') + '<button type="button" class="editor-image__remove"><svg class="icon"><use href="#icon-close"></use></svg></button>';
      div.querySelector('.editor-image__remove').addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!editBuffer) return;
        editBuffer.imageIds = (editBuffer.imageIds || []).filter(x => x !== imgId);
        if (editBuffer.coverImageId === imgId) editBuffer.coverImageId = null;
        div.remove();
        if (editBuffer.id && !lastEditImages.has(imgId)) await Images.remove(imgId);
      });
      div.addEventListener('click', () => {
        if (!editBuffer) return;
        editBuffer.coverImageId = imgId;
        list.querySelectorAll('.editor-image').forEach(t => {
          t.classList.toggle('is-cover', t.dataset.id === imgId);
          const b = t.querySelector('.editor-image__badge');
          if (t.dataset.id === imgId && !b) { const s = document.createElement('span'); s.className = 'editor-image__badge'; s.textContent = 'غلاف'; t.appendChild(s); }
          else if (t.dataset.id !== imgId && b) b.remove();
        });
        Images.getUrl(imgId).then(u => { if (u) $('editor-cover-preview').innerHTML = '<img src="' + u + '" alt="">'; });
      });
      list.appendChild(div);
    }
    async function setEditCover(id) {
      if (!editBuffer) return;
      editBuffer.coverImageId = id;
      if (id) { const u = await Images.getUrl(id); if (u) $('editor-cover-preview').innerHTML = '<img src="' + u + '" alt="">'; }
      else $('editor-cover-preview').innerHTML = '<svg class="icon icon--xl"><use href="#icon-image"></use></svg>';
    }
    async function handleCover(files) {
      if (!editBuffer || !files.length) return;
      const ids = await Images.addFiles(editBuffer.id || 'temp', files);
      if (ids.length) { editBuffer.imageIds = editBuffer.imageIds || []; editBuffer.imageIds.push(ids[0]); editBuffer.coverImageId = ids[0]; await addEditorImageThumb(ids[0], true); await setEditCover(ids[0]); }
    }
    async function handleImages(files) {
      if (!editBuffer || !files.length) return;
      const ids = await Images.addFiles(editBuffer.id || 'temp', files);
      editBuffer.imageIds = editBuffer.imageIds || [];
      for (const id of ids) { editBuffer.imageIds.push(id); await addEditorImageThumb(id, false); }
    }
    async function saveEditor() {
      if (!editBuffer) return;
      const name = ($('editor-name').value || '').trim();
      if (!name) { const e = $('editor-name-error'); e.textContent = 'اسم الكارت مطلوب'; e.classList.add('is-visible'); $('editor-name').focus(); throw new Error('اسم الكارت مطلوب'); }
      editBuffer.name = name;
      editBuffer.categoryId = $('editor-category').value || 'other';
      editBuffer.description = $('editor-description').value || '';
      editBuffer.username = $('editor-username').value || '';
      editBuffer.password = $('editor-password').value || '';
      editBuffer.email = $('editor-email').value || '';
      editBuffer.phone = $('editor-phone').value || '';
      editBuffer.accountId = $('editor-account-id').value || '';
      editBuffer.recoveryEmail = $('editor-recovery-email').value || '';
      editBuffer.notes = $('editor-notes').value || '';
      editBuffer.customFields = [];
      document.querySelectorAll('#custom-fields-list .custom-field').forEach(row => {
        const label = row.querySelector('[data-role="label"]').value.trim();
        const value = row.querySelector('[data-role="value"]').value;
        if (label || value) editBuffer.customFields.push({ id: row.dataset.id, label, value });
      });
      editBuffer.links = [];
      document.querySelectorAll('#links-list .link-editor').forEach(row => {
        const title = row.querySelector('[data-role="title"]').value.trim();
        const url = row.querySelector('[data-role="url"]').value.trim();
        const description = row.querySelector('[data-role="description"]').value.trim();
        if (title || url) editBuffer.links.push({ id: row.dataset.id, title, url, description });
      });
      if (!editBuffer.id) { editBuffer.id = uid(); editBuffer.createdAt = Date.now(); }
      editBuffer.updatedAt = Date.now();
      await DB.putCard({ id: editBuffer.id, favorite: !!editBuffer.favorite, createdAt: editBuffer.createdAt, updatedAt: editBuffer.updatedAt, payload: await Crypto.encJson(Auth.getVaultKey(), editBuffer) });
      for (const imgId of editBuffer.imageIds || []) { const rec = await DB.getImage(imgId); if (rec && rec.cardId === 'temp') { rec.cardId = editBuffer.id; await DB.putImage(rec); } }
      for (const oldImgId of lastEditImages) if (!(editBuffer.imageIds || []).includes(oldImgId)) await Images.remove(oldImgId);
      cache.set(editBuffer.id, editBuffer);
      editBuffer = null;
    }
    function refresh() { renderDashboard(); renderFavoritesPage(); renderCategoriesPage(); renderChips(); }
    return { loadAll, loadCategories, getCategories, getCategory, getAll, getById, renderDashboard, renderFavoritesPage, renderCategoriesPage, renderChips, renderDetails, openEditor, saveEditor, deleteCard, toggleFavorite, addCustomField: () => addCustomFieldRow({}), addLink: () => addLinkRow({}), addCategory, handleCover, handleImages, setEditCover, refresh };
  })();

  const Settings = (() => {
    function openChangeMaster() {
      const content = document.createElement('div');
      content.innerHTML = '<div class="field"><label class="field__label">كلمة السر الرئيسية الحالية</label><div class="field__control"><input type="password" class="field__input" id="cm-cur-m"></div></div>' +
        '<div class="field"><label class="field__label">كلمة السر الثانية الحالية</label><div class="field__control"><input type="password" class="field__input" id="cm-cur-s"></div></div>' +
        '<div class="field"><label class="field__label">كلمة السر الرئيسية الجديدة</label><div class="field__control"><input type="password" class="field__input" id="cm-new-m"></div></div>';
      App.openModal({ title: 'تغيير كلمة السر الرئيسية', content, actions: [{ label: 'إلغاء', className: 'btn--ghost' }, { label: 'تغيير', className: 'btn--primary', onClick: async () => { try { await Auth.changeMasterPassword($('cm-cur-m').value, $('cm-cur-s').value, $('cm-new-m').value); App.toast('تم التغيير', 'success'); } catch (e) { App.toast(e.message || 'فشل', 'error'); return false; } } }] });
    }
    function openChangeSecond() {
      const content = document.createElement('div');
      content.innerHTML = '<div class="field"><label class="field__label">كلمة السر الرئيسية الحالية</label><div class="field__control"><input type="password" class="field__input" id="cs-cur-m"></div></div>' +
        '<div class="field"><label class="field__label">كلمة السر الثانية الحالية</label><div class="field__control"><input type="password" class="field__input" id="cs-cur-s"></div></div>' +
        '<div class="field"><label class="field__label">كلمة السر الثانية الجديدة</label><div class="field__control"><input type="password" class="field__input" id="cs-new-s"></div></div>';
      App.openModal({ title: 'تغيير كلمة السر الثانية', content, actions: [{ label: 'إلغاء', className: 'btn--ghost' }, { label: 'تغيير', className: 'btn--primary', onClick: async () => { try { await Auth.changeSecondPassword($('cs-cur-m').value, $('cs-cur-s').value, $('cs-new-s').value); App.toast('تم التغيير', 'success'); } catch (e) { App.toast(e.message || 'فشل', 'error'); return false; } } }] });
    }
    function refresh() {
      if ($('setting-theme')) $('setting-theme').value = App.readSetting('theme', 'dark');
      if ($('setting-autolock')) $('setting-autolock').value = String(App.readSetting('autolock', 5));
      if ($('setting-visibility')) $('setting-visibility').value = String(App.readSetting('visibility', 15));
      if ($('setting-clipboard')) $('setting-clipboard').value = String(App.readSetting('clipboard', 30));
      if ($('setting-sort')) $('setting-sort').value = App.readSetting('sort', 'modified');
    }
    function init() { refresh(); }
    return { init, refresh, openChangeMaster, openChangeSecond };
  })();

  const App = (() => {
    const LS = { theme: 'mv.theme', autolock: 'mv.autolock', visibility: 'mv.visibility', clipboard: 'mv.clipboard', sort: 'mv.sort' };
    const DEFAULTS = { theme: 'dark', autolock: 5, visibility: 15, clipboard: 30, sort: 'modified' };
    const SORT_LABELS = { modified: 'الأحدث', name: 'الاسم', created: 'الإنشاء' };
    const INITIAL = { master: 'ahmedmohamedgamal', second: '9118' };
    const state = { booted: false, view: 'dashboard', previousView: null, searchQuery: '', activeCategory: 'all', sortMode: 'modified', currentCardId: null, editingCardId: null, autolockTimerId: null, clipboardTimerId: null, tempMaster: null, viewerImages: [], viewerIndex: 0 };

    function readSetting(k, fb) { try { const v = localStorage.getItem(LS[k]); if (v === null) return fb; if (['autolock', 'visibility', 'clipboard'].includes(k)) { const n = parseInt(v, 10); return isFinite(n) ? n : fb; } return v; } catch (e) { return fb; } }
    function writeSetting(k, v) { try { localStorage.setItem(LS[k], String(v)); } catch (e) { } }
    function applyTheme(t) { const th = t === 'light' ? 'light' : 'dark'; document.documentElement.setAttribute('data-theme', th); const m = document.querySelector('meta[name="theme-color"]'); if (m) m.setAttribute('content', th === 'light' ? '#f6f8fb' : '#0a0c10'); }
    function toast(msg, type, dur) {
      const root = $('toast-root'); if (!root) return;
      const t = document.createElement('div');
      t.className = 'toast toast--' + (type || 'info');
      const ic = type === 'success' ? 'icon-check' : type === 'error' ? 'icon-alert' : 'icon-info';
      t.innerHTML = '<span class="toast__icon"><svg class="icon icon--sm"><use href="#' + ic + '"></use></svg></span><span class="toast__message">' + esc(msg) + '</span>';
      root.appendChild(t);
      setTimeout(() => { t.classList.add('is-out'); setTimeout(() => t.remove(), 300); }, dur || 3000);
    }
    let confirmResolve = null;
    function confirm(opts) {
      return new Promise(res => {
        const root = $('confirm-root'); if (!root) { res(false); return; }
        $('confirm-title').textContent = opts.title || 'تأكيد';
        $('confirm-text').textContent = opts.text || '';
        $('confirm-ok').textContent = opts.confirmText || 'تأكيد';
        $('confirm-cancel').textContent = 'إلغاء';
        $('confirm-ok').className = 'btn ' + (opts.danger ? 'btn--danger' : 'btn--primary');
        confirmResolve = res;
        root.hidden = false;
      });
    }
    function resolveConfirm(v) { const root = $('confirm-root'); if (root) root.hidden = true; if (confirmResolve) { const r = confirmResolve; confirmResolve = null; r(v); } }
    function openModal(opts) {
      const root = $('modal-root'); if (!root) return;
      $('modal-title').textContent = opts.title || '';
      const body = $('modal-body'); body.innerHTML = '';
      if (typeof opts.content === 'string') body.innerHTML = opts.content;
      else if (opts.content instanceof Node) body.appendChild(opts.content);
      const actions = $('modal-actions'); actions.innerHTML = '';
      (opts.actions || []).forEach(a => {
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'btn ' + (a.className || 'btn--ghost'); b.textContent = a.label;
        b.addEventListener('click', async () => { if (typeof a.onClick === 'function') { const r = await a.onClick(); if (r === false) return; } closeModal(); });
        actions.appendChild(b);
      });
      root.hidden = false;
    }
    function closeModal() { const r = $('modal-root'); if (r) r.hidden = true; }
    async function copy(text, sensitive) {
      if (!text) { toast('لا يوجد شيء للنسخ', 'error'); return; }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
        else { const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
        toast('تم النسخ', 'success', 1800);
        if (sensitive) {
          if (state.clipboardTimerId) clearTimeout(state.clipboardTimerId);
          const s = readSetting('clipboard', DEFAULTS.clipboard);
          state.clipboardTimerId = setTimeout(() => { try { navigator.clipboard && navigator.clipboard.writeText && navigator.clipboard.writeText('').catch(() => { }); } catch (e) { } }, s * 1000);
        }
      } catch (e) { toast('تعذّر النسخ', 'error'); }
    }
    function navigate(view) {
      state.view = view;
      ['dashboard', 'favorites', 'categories', 'settings', 'details', 'editor'].forEach(v => { const el = $('view-' + v); if (el) el.hidden = v !== view; });
      const secondary = view === 'details' || view === 'editor';
      const hdr = $('app-header'), nav = $('bottom-nav'), fab = $('fab-add');
      if (hdr) hdr.hidden = secondary;
      if (nav) nav.hidden = secondary;
      if (fab) fab.hidden = secondary || view === 'settings';
      if (!secondary && nav) nav.querySelectorAll('.nav-item').forEach(b => { const on = b.getAttribute('data-nav') === view; b.classList.toggle('is-active', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
      const sub = $('header-subtitle');
      if (sub) sub.textContent = { dashboard: 'الخزنة الشخصية', favorites: 'المفضلة', categories: 'الأقسام', settings: 'الإعدادات' }[view] || 'الخزنة الشخصية';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    function openDetails(id) { state.currentCardId = id; state.previousView = state.view; navigate('details'); Cards.renderDetails(id).catch(e => { console.error(e); toast('تعذّر التحميل', 'error'); }); }
    function openEditor(id) { state.editingCardId = id || null; state.previousView = state.view; navigate('editor'); $('editor-title').textContent = id ? 'تعديل الكارت' : 'كارت جديد'; Cards.openEditor(id).catch(e => { console.error(e); toast('تعذّر الفتح', 'error'); }); }
    function closeEditor() { const back = state.previousView && state.previousView !== 'editor' ? state.previousView : 'dashboard'; state.editingCardId = null; navigate(back); }
    function scheduleAutolock() { clearAutolock(); if (!Auth.isUnlocked()) return; const m = readSetting('autolock', DEFAULTS.autolock); if (!m || m <= 0) return; state.autolockTimerId = setTimeout(() => lock('timeout'), m * 60 * 1000); }
    function clearAutolock() { if (state.autolockTimerId) { clearTimeout(state.autolockTimerId); state.autolockTimerId = null; } }
    function resetAutolock() { if (Auth.isUnlocked()) scheduleAutolock(); }
    function lock(reason) {
      clearAutolock();
      Images.clearCache();
      Auth.lock();
      const app = $('app-shell'); if (app) app.hidden = true;
      const l = $('lock-overlay'); if (l) l.hidden = false;
      if (reason === 'timeout') toast('اتقفلت الخزنة تلقائياً', 'info');
      else if (reason === 'manual') toast('اتقفلت الخزنة', 'info');
    }
    function showAuth() { const a = $('auth-screen'); if (a) a.hidden = false; stepAuth(1); setTimeout(() => { const i = $('auth-password-1'); if (i) i.focus(); }, 350); }
    function stepAuth(n) {
      $('auth-step-1').hidden = n !== 1; $('auth-step-2').hidden = n !== 2;
      document.querySelectorAll('[data-step-dot]').forEach(d => d.classList.toggle('is-active', parseInt(d.getAttribute('data-step-dot'), 10) <= n));
      clearAuthErrors();
      if (n === 2) setTimeout(() => { const i = $('auth-password-2'); if (i) i.focus(); }, 250);
    }
    function clearAuthErrors() { ['auth-error-1', 'auth-error-2'].forEach(id => { const el = $(id); if (el) { el.textContent = ''; el.classList.remove('is-visible'); } }); document.querySelectorAll('#auth-screen .field__control.is-invalid').forEach(el => el.classList.remove('is-invalid')); }
    function setAuthError(n, msg) { const el = $('auth-error-' + n); if (el) { el.textContent = msg; el.classList.add('is-visible'); } const inp = $('auth-password-' + n); if (inp && inp.parentElement) inp.parentElement.classList.add('is-invalid'); const card = document.querySelector('.auth__card'); if (card) { card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake'); } }
    async function submitAuth1() {
      const p = $('auth-password-1').value;
      if (!p) { setAuthError(1, 'اكتب كلمة السر'); return; }
      const btn = $('auth-submit-1'); btn.disabled = true; const sp = btn.querySelector('.btn__spinner'); if (sp) sp.hidden = false;
      try { if (!await Auth.verifyMaster(p)) { setAuthError(1, 'كلمة السر الرئيسية غلط'); return; } state.tempMaster = p; clearAuthErrors(); stepAuth(2); }
      catch (e) { console.error(e); setAuthError(1, 'خطأ، حاول تاني'); }
      finally { btn.disabled = false; if (sp) sp.hidden = true; }
    }
    async function submitAuth2() {
      const p = $('auth-password-2').value;
      if (!state.tempMaster) { stepAuth(1); return; }
      if (!p) { setAuthError(2, 'اكتب كلمة السر التانية'); return; }
      const btn = $('auth-submit-2'); btn.disabled = true; const sp = btn.querySelector('.btn__spinner'); if (sp) sp.hidden = false;
      try {
        if (!await Auth.verifySecond(p)) { setAuthError(2, 'كلمة السر الثانية غلط'); return; }
        await Auth.completeLogin(state.tempMaster, p);
        state.tempMaster = null;
        clearAuthErrors();
        $('auth-screen').hidden = true;
        $('lock-overlay').hidden = true;
        $('app-shell').hidden = false;
        await Cards.loadCategories();
        await Cards.loadAll();
        Cards.refresh();
        navigate('dashboard');
        updateStorage();
        scheduleAutolock();
        toast('أهلاً بيك في خزنتك', 'success');
      } catch (e) { console.error(e); setAuthError(2, 'خطأ في الدخول'); }
      finally { btn.disabled = false; if (sp) sp.hidden = true; }
    }
    async function updateStorage() {
      try { if (navigator.storage && navigator.storage.estimate) { const e = await navigator.storage.estimate(); const used = e.usage || 0, quota = e.quota || 0; if ($('storage-used')) $('storage-used').textContent = fmtBytes(used); if ($('storage-quota')) $('storage-quota').textContent = fmtBytes(quota); if ($('storage-bar-fill')) $('storage-bar-fill').style.width = Math.min(100, quota > 0 ? used / quota * 100 : 0) + '%'; } } catch (e) { }
      try { const s = await DB.stats(); if ($('stat-cards')) $('stat-cards').textContent = s.cards; if ($('stat-images')) $('stat-images').textContent = s.images; if ($('stat-categories')) $('stat-categories').textContent = s.categories; } catch (e) { }
    }
    function openViewer(ids, start) { state.viewerImages = ids || []; state.viewerIndex = start || 0; showViewerImage(); $('image-viewer').hidden = false; }
    async function showViewerImage() { if (!state.viewerImages.length) return; const id = state.viewerImages[state.viewerIndex]; const url = await Images.getUrl(id); if (url) $('viewer-image').src = url; $('viewer-counter').textContent = (state.viewerIndex + 1) + ' / ' + state.viewerImages.length; }
    function viewerPrev() { if (state.viewerIndex > 0) { state.viewerIndex--; showViewerImage(); } }
    function viewerNext() { if (state.viewerIndex < state.viewerImages.length - 1) { state.viewerIndex++; showViewerImage(); } }
    function closeViewer() { $('image-viewer').hidden = true; state.viewerImages = []; }

    function bind() {
      $('auth-step-1').addEventListener('submit', e => { e.preventDefault(); submitAuth1(); });
      $('auth-step-2').addEventListener('submit', e => { e.preventDefault(); submitAuth2(); });
      $('auth-back-2').addEventListener('click', () => { state.tempMaster = null; stepAuth(1); });
      $$('[data-toggle-target]').forEach(btn => {
        btn.addEventListener('click', () => {
          const t = $(btn.getAttribute('data-toggle-target')); if (!t) return;
          const reveal = t.type === 'password';
          t.type = reveal ? 'text' : 'password';
          btn.setAttribute('aria-pressed', reveal ? 'true' : 'false');
          btn.classList.toggle('is-revealed', reveal);
          const u = btn.querySelector('use'); if (u) u.setAttribute('href', reveal ? '#icon-eye-off' : '#icon-eye');
        });
      });
      $('btn-unlock').addEventListener('click', () => { $('lock-overlay').hidden = true; showAuth(); });
      $$('.nav-item').forEach(b => b.addEventListener('click', () => navigate(b.getAttribute('data-nav'))));
      $('btn-lock').addEventListener('click', () => lock('manual'));
      $('btn-settings-header').addEventListener('click', () => navigate('settings'));
      const sIn = $('search-input'), sCl = $('search-clear');
      sIn.addEventListener('input', () => { state.searchQuery = sIn.value.trim(); sCl.hidden = !state.searchQuery; Cards.renderDashboard(); });
      sCl.addEventListener('click', () => { sIn.value = ''; state.searchQuery = ''; sCl.hidden = true; sIn.focus(); Cards.renderDashboard(); });
      const sortBtn = $('btn-sort');
      sortBtn.addEventListener('click', () => { const o = ['modified', 'name', 'created']; state.sortMode = o[(o.indexOf(state.sortMode) + 1) % o.length]; $('sort-label').textContent = SORT_LABELS[state.sortMode]; Cards.renderDashboard(); Cards.renderFavoritesPage(); });
      $('sort-label').textContent = SORT_LABELS[state.sortMode];
      $('fab-add').addEventListener('click', () => openEditor(null));
      $('btn-empty-add').addEventListener('click', () => openEditor(null));
      $('btn-editor-back').addEventListener('click', closeEditor);
      $('btn-editor-cancel').addEventListener('click', closeEditor);
      $('card-form').addEventListener('submit', async e => { e.preventDefault(); try { await Cards.saveEditor(); toast('تم حفظ الكارت', 'success'); closeEditor(); Cards.refresh(); updateStorage(); } catch (err) { console.error(err); if (err.message !== 'اسم الكارت مطلوب') toast(err.message || 'تعذّر الحفظ', 'error'); } });
      $('btn-add-custom-field').addEventListener('click', () => Cards.addCustomField());
      $('btn-add-link').addEventListener('click', () => Cards.addLink());
      $('btn-editor-add-images').addEventListener('click', () => { const i = $('editor-images-input'); i.value = ''; i.click(); });
      $('btn-editor-pick-cover').addEventListener('click', () => { const i = $('editor-cover-input'); i.value = ''; i.click(); });
      $('btn-editor-remove-cover').addEventListener('click', () => Cards.setEditCover(null));
      $('editor-images-input').addEventListener('change', e => Cards.handleImages(Array.from(e.target.files)));
      $('editor-cover-input').addEventListener('change', e => Cards.handleCover(Array.from(e.target.files)));
      $('btn-details-back').addEventListener('click', () => navigate(state.previousView || 'dashboard'));
      $('btn-details-favorite').addEventListener('click', () => state.currentCardId && Cards.toggleFavorite(state.currentCardId));
      $('btn-details-edit').addEventListener('click', () => state.currentCardId && openEditor(state.currentCardId));
      $('btn-details-edit-bottom').addEventListener('click', () => state.currentCardId && openEditor(state.currentCardId));
      $('btn-details-delete').addEventListener('click', async () => {
        if (!state.currentCardId) return;
        const ok = await confirm({ title: 'حذف الكارت', text: 'متأكد عايز تحذف الكارت ده نهائياً؟', confirmText: 'احذف', danger: true });
        if (!ok) return;
        await Cards.deleteCard(state.currentCardId);
        toast('تم الحذف', 'success');
        state.currentCardId = null;
        navigate('dashboard'); Cards.refresh(); updateStorage();
      });
      $('btn-add-category').addEventListener('click', () => Cards.addCategory());
      $('setting-theme').addEventListener('change', e => { applyTheme(e.target.value); writeSetting('theme', e.target.value); });
      $('setting-autolock').addEventListener('change', e => { writeSetting('autolock', e.target.value); resetAutolock(); });
      $('setting-visibility').addEventListener('change', e => writeSetting('visibility', e.target.value));
      $('setting-clipboard').addEventListener('change', e => writeSetting('clipboard', e.target.value));
      $('setting-sort').addEventListener('change', e => { state.sortMode = e.target.value; $('sort-label').textContent = SORT_LABELS[state.sortMode]; writeSetting('sort', state.sortMode); Cards.renderDashboard(); Cards.renderFavoritesPage(); });
      $('btn-change-master').addEventListener('click', () => Settings.openChangeMaster());
      $('btn-change-second').addEventListener('click', () => Settings.openChangeSecond());
      $('btn-clear-data').addEventListener('click', async () => {
        const ok = await confirm({ title: 'حذف كل البيانات', text: 'هيتم حذف كل الكروت والصور والأقسام وبيانات الدخول نهائياً. مش ممكن التراجع.', confirmText: 'احذف كل حاجة', danger: true });
        if (!ok) return;
        try { await DB.clearAll(); localStorage.clear(); toast('اتحذف كل حاجة', 'success'); setTimeout(() => location.reload(), 800); }
        catch (e) { toast('تعذّر الحذف', 'error'); }
      });
      $('confirm-ok').addEventListener('click', () => resolveConfirm(true));
      $('confirm-cancel').addEventListener('click', () => resolveConfirm(false));
      $('confirm-root').addEventListener('click', e => { if (e.target === $('confirm-root')) resolveConfirm(false); });
      $('modal-close').addEventListener('click', closeModal);
      $('modal-root').addEventListener('click', e => { if (e.target === $('modal-root')) closeModal(); });
      $('viewer-close').addEventListener('click', closeViewer);
      $('viewer-prev').addEventListener('click', viewerPrev);
      $('viewer-next').addEventListener('click', viewerNext);
      $('viewer-delete').addEventListener('click', async () => {
        if (!state.viewerImages.length) return;
        const id = state.viewerImages[state.viewerIndex];
        const ok = await confirm({ title: 'حذف الصورة', text: 'تحذف الصورة دي؟', confirmText: 'احذف', danger: true });
        if (!ok) return;
        await Images.remove(id);
        state.viewerImages.splice(state.viewerIndex, 1);
        if (state.viewerImages.length === 0) closeViewer();
        else { state.viewerIndex = Math.min(state.viewerIndex, state.viewerImages.length - 1); showViewerImage(); }
        if (state.currentCardId) Cards.renderDetails(state.currentCardId);
      });
      document.addEventListener('visibilitychange', () => { if (!Auth.isUnlocked()) return; $('privacy-curtain').hidden = document.visibilityState !== 'hidden'; if (document.visibilityState === 'visible') resetAutolock(); });
      window.addEventListener('blur', () => { if (Auth.isUnlocked()) $('privacy-curtain').hidden = false; });
      window.addEventListener('focus', () => { if (Auth.isUnlocked()) { $('privacy-curtain').hidden = true; resetAutolock(); } });
      ['click', 'keydown', 'touchstart', 'mousemove', 'scroll'].forEach(ev => document.addEventListener(ev, resetAutolock, { passive: true }));
      document.addEventListener('click', e => { const btn = e.target.closest('[data-copy-target]'); if (btn) { e.preventDefault(); const t = $(btn.getAttribute('data-copy-target')); if (t) copy(t.value, btn.getAttribute('data-sensitive') === 'true'); } });
      document.addEventListener('keydown', e => { if (e.key === 'Escape') { if (!$('modal-root').hidden) closeModal(); else if (!$('confirm-root').hidden) resolveConfirm(false); else if (!$('image-viewer').hidden) closeViewer(); } });
      Auth.onLock(() => { const app = $('app-shell'); if (app) app.hidden = true; const l = $('lock-overlay'); if (l) l.hidden = false; });
    }

    async function boot() {
      if (state.booted) return; state.booted = true;
      applyTheme(readSetting('theme', DEFAULTS.theme));
      state.sortMode = readSetting('sort', DEFAULTS.sort);
      try { await DB.init(); } catch (e) { console.error('DB init failed', e); }
      try { await Auth.init(); } catch (e) { console.error('Auth init failed', e); }
      Settings.init();
      try { const st = await Crypto.selfTest(); console.info('[MV] crypto self-test:', st); } catch (e) { console.warn('[MV] self-test error', e); }
      try { if (!await Auth.hasSetup()) { await Auth.setup(INITIAL.master, INITIAL.second); console.info('[MV] initial setup done — change passwords!'); } }
      catch (e) { console.error('setup failed', e); }
      setTimeout(() => { const sp = $('splash-screen'); if (sp) { sp.classList.add('is-hidden'); setTimeout(() => { sp.hidden = true; }, 500); } }, 400);
      showAuth();
      const online = $('app-online');
      if (online) online.textContent = navigator.onLine ? 'متصل' : 'غير متصل';
      window.addEventListener('online', () => { if (online) online.textContent = 'متصل'; });
      window.addEventListener('offline', () => { if (online) online.textContent = 'غير متصل'; });
      const stand = $('app-standalone');
      if (stand) stand.textContent = (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone) ? 'مثبّت' : 'متصفح';
    }

    return { state, toast, confirm, openModal, closeModal, copy, navigate, openDetails, openEditor, closeEditor, lock, readSetting, writeSetting, openViewer, boot, bind, updateStorage };
  })();

  window.MV = { Crypto, DB, Auth, Images, Cards, Settings, App };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { App.bind(); App.boot(); }, { once: true });
  else { App.bind(); App.boot(); }
})();
