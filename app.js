(function () {
  'use strict';

  const $ = function (id) { return document.getElementById(id); };
  const $$ = function (sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); };

  const LS = {
    theme: 'mv.theme',
    autolock: 'mv.autolock',
    visibility: 'mv.visibility',
    clipboard: 'mv.clipboard',
    sort: 'mv.sort'
  };

  const DEFAULTS = {
    theme: 'dark',
    autolock: 5,
    visibility: 15,
    clipboard: 30,
    sort: 'modified'
  };

  const SORT_LABELS = {
    modified: 'الأحدث',
    name: 'الاسم',
    created: 'الإنشاء'
  };

  const INITIAL_SETUP = {
    master: 'ahmedmohamedgamal',
    second: '9118'
  };

  const state = {
    booted: false,
    unlocked: false,
    view: 'dashboard',
    previousView: null,
    searchQuery: '',
    activeCategory: 'all',
    sortMode: 'modified',
    currentCardId: null,
    editingCardId: null,
    autolockTimerId: null,
    clipboardTimerId: null,
    visibilityTimers: {}
  };

  function readSetting(key, fallback) {
    try {
      const v = localStorage.getItem(LS[key]);
      if (v === null) return fallback;
      if (key === 'autolock' || key === 'visibility' || key === 'clipboard') {
        const n = parseInt(v, 10);
        return isFinite(n) ? n : fallback;
      }
      return v;
    } catch (e) {
      return fallback;
    }
  }

  function writeSetting(key, value) {
    try {
      localStorage.setItem(LS[key], String(value));
    } catch (e) {}
  }

  function applyTheme(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', t === 'light' ? '#f6f8fb' : '#0a0c10');
    const sel = $('setting-theme');
    if (sel) sel.value = t;
  }

  function toast(message, type, duration) {
    const root = $('toast-root');
    if (!root) return;
    const t = document.createElement('div');
    t.className = 'toast toast--' + (type || 'info');
    const icon = type === 'success' ? 'icon-check' : type === 'error' ? 'icon-alert' : 'icon-info';
    t.innerHTML = '<span class="toast__icon"><svg class="icon icon--sm"><use href="#' + icon + '"></use></svg></span><span class="toast__message"></span>';
    t.querySelector('.toast__message').textContent = message;
    root.appendChild(t);
    const ms = duration || 3000;
    setTimeout(function () {
      t.classList.add('is-out');
      setTimeout(function () {
        if (t.parentNode) t.parentNode.removeChild(t);
      }, 300);
    }, ms);
  }

  let confirmResolver = null;

  function confirmAction(opts) {
    return new Promise(function (resolve) {
      const root = $('confirm-root');
      if (!root) { resolve(false); return; }
      $('confirm-title').textContent = opts.title || 'تأكيد';
      $('confirm-text').textContent = opts.text || '';
      $('confirm-ok').textContent = opts.confirmText || 'تأكيد';
      $('confirm-cancel').textContent = opts.cancelText || 'إلغاء';
      $('confirm-ok').className = 'btn ' + (opts.danger ? 'btn--danger' : 'btn--primary');
      confirmResolver = resolve;
      root.hidden = false;
    });
  }

  function resolveConfirm(value) {
    const root = $('confirm-root');
    if (root) root.hidden = true;
    if (confirmResolver) {
      const r = confirmResolver;
      confirmResolver = null;
      r(value);
    }
  }

  function openModal(opts) {
    const root = $('modal-root');
    if (!root) return;
    $('modal-title').textContent = opts.title || '';
    const body = $('modal-body');
    body.innerHTML = '';
    if (typeof opts.content === 'string') body.innerHTML = opts.content;
    else if (opts.content instanceof Node) body.appendChild(opts.content);
    const actions = $('modal-actions');
    actions.innerHTML = '';
    (opts.actions || []).forEach(function (a) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn ' + (a.className || 'btn--ghost');
      btn.textContent = a.label;
      btn.addEventListener('click', function () {
        if (typeof a.onClick === 'function') {
          const r = a.onClick();
          if (r === false) return;
        }
        closeModal();
      });
      actions.appendChild(btn);
    });
    root.hidden = false;
    if (typeof opts.onMount === 'function') opts.onMount(body);
  }

  function closeModal() {
    const root = $('modal-root');
    if (root) root.hidden = true;
  }

  function hideSplash() {
    const splash = $('splash-screen');
    if (!splash) return;
    splash.classList.add('is-hidden');
    setTimeout(function () { splash.hidden = true; }, 500);
  }

  function showAuth() {
    const auth = $('auth-screen');
    if (auth) auth.hidden = false;
    showAuthStep(1);
    setTimeout(function () {
      const inp = $('auth-password-1');
      if (inp) inp.focus();
    }, 350);
  }

  function showAuthStep(n) {
    const s1 = $('auth-step-1');
    const s2 = $('auth-step-2');
    const dots = document.querySelectorAll('[data-step-dot]');
    if (s1) s1.hidden = n !== 1;
    if (s2) s2.hidden = n !== 2;
    dots.forEach(function (d) {
      d.classList.toggle('is-active', parseInt(d.getAttribute('data-step-dot'), 10) <= n);
    });
    clearAuthErrors();
    if (n === 2) {
      setTimeout(function () {
        const inp = $('auth-password-2');
        if (inp) inp.focus();
      }, 250);
    }
  }

  function clearAuthErrors() {
    ['auth-error-1', 'auth-error-2'].forEach(function (id) {
      const el = $(id);
      if (el) { el.textContent = ''; el.classList.remove('is-visible'); }
    });
    document.querySelectorAll('#auth-screen .field__control.is-invalid').forEach(function (el) {
      el.classList.remove('is-invalid');
    });
  }

  function setAuthError(n, message) {
    const el = $('auth-error-' + n);
    if (el) { el.textContent = message; el.classList.add('is-visible'); }
    const inp = $('auth-password-' + n);
    if (inp && inp.parentElement) inp.parentElement.classList.add('is-invalid');
    const card = document.querySelector('.auth__card');
    if (card) {
      card.classList.remove('shake');
      void card.offsetWidth;
      card.classList.add('shake');
    }
  }

  function showApp() {
    const auth = $('auth-screen');
    if (auth) auth.hidden = true;
    const shell = $('app-shell');
    if (shell) shell.hidden = false;
    state.unlocked = true;
    state.view = 'dashboard';
    navigate('dashboard');
    refreshAll();
  }

  function showLockOverlay() {
    const lock = $('lock-overlay');
    if (lock) lock.hidden = false;
  }

  function hideLockOverlay() {
    const lock = $('lock-overlay');
    if (lock) lock.hidden = true;
  }

  function navigate(view) {
    const views = ['dashboard', 'favorites', 'categories', 'settings', 'details', 'editor'];
    if (views.indexOf(view) === -1) return;
    state.view = view;
    views.forEach(function (v) {
      const el = $('view-' + v);
      if (el) el.hidden = v !== view;
    });
    const header = $('app-header');
    const nav = $('bottom-nav');
    const fab = $('fab-add');
    const isSecondary = view === 'details' || view === 'editor';
    if (header) header.hidden = isSecondary;
    if (nav) nav.hidden = isSecondary;
    if (fab) fab.hidden = isSecondary || view === 'settings';
    if (!isSecondary && nav) {
      nav.querySelectorAll('.nav-item').forEach(function (b) {
        const on = b.getAttribute('data-nav') === view;
        b.classList.toggle('is-active', on);
        if (on) b.setAttribute('aria-current', 'page');
        else b.removeAttribute('aria-current');
      });
    }
    const subtitle = $('header-subtitle');
    if (subtitle) {
      const map = {
        dashboard: 'الخزنة الشخصية',
        favorites: 'المفضلة',
        categories: 'الأقسام',
        settings: 'الإعدادات'
      };
      subtitle.textContent = map[view] || 'الخزنة الشخصية';
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (window.MV && MV.App && typeof MV.App.onNavigate === 'function') {
      try { MV.App.onNavigate(view); } catch (e) {}
    }
  }

  function openDetails(cardId) {
    state.currentCardId = cardId;
    state.previousView = state.view;
    navigate('details');
    if (window.MV && MV.Cards && typeof MV.Cards.renderDetails === 'function') {
      Promise.resolve(MV.Cards.renderDetails(cardId)).catch(function (e) {
        console.error('[MV] renderDetails failed', e);
        toast('تعذّر تحميل تفاصيل الكارت', 'error');
      });
    }
  }

  function openEditor(cardId) {
    state.editingCardId = cardId || null;
    state.previousView = state.view;
    navigate('editor');
    const title = $('editor-title');
    if (title) title.textContent = cardId ? 'تعديل الكارت' : 'كارت جديد';
    if (window.MV && MV.Cards && typeof MV.Cards.openEditor === 'function') {
      Promise.resolve(MV.Cards.openEditor(cardId)).catch(function (e) {
        console.error('[MV] openEditor failed', e);
        toast('تعذّر فتح المحرر', 'error');
      });
    }
  }

  function closeEditor() {
    const backTo = state.previousView && state.previousView !== 'editor' ? state.previousView : 'dashboard';
    state.editingCardId = null;
    navigate(backTo);
  }

  function refreshAll() {
    if (window.MV && MV.Cards && typeof MV.Cards.refresh === 'function') {
      try { MV.Cards.refresh(); } catch (e) { console.error(e); }
    }
    if (window.MV && MV.Settings && typeof MV.Settings.refresh === 'function') {
      try { MV.Settings.refresh(); } catch (e) { console.error(e); }
    }
    updateStorageInfo();
  }

  async function updateStorageInfo() {
    try {
      if (navigator.storage && navigator.storage.estimate) {
        const est = await navigator.storage.estimate();
        const used = est.usage || 0;
        const quota = est.quota || 0;
        const usedEl = $('storage-used');
        const quotaEl = $('storage-quota');
        const barEl = $('storage-bar-fill');
        if (usedEl) usedEl.textContent = formatBytes(used);
        if (quotaEl) quotaEl.textContent = formatBytes(quota);
        if (barEl) barEl.style.width = Math.min(100, quota > 0 ? (used / quota) * 100 : 0) + '%';
      }
    } catch (e) {}
    try {
      if (window.MV && MV.DB && typeof MV.DB.stats === 'function') {
        const s = await MV.DB.stats();
        setText('stat-cards', s.cards || 0);
        setText('stat-images', s.images || 0);
        setText('stat-categories', s.categories || 0);
      }
    } catch (e) {}
  }

  function setText(id, v) {
    const el = $(id);
    if (el) el.textContent = String(v);
  }

  function formatBytes(bytes) {
    if (!bytes || bytes < 1) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
  }

  function scheduleAutolock() {
    clearAutolock();
    if (!state.unlocked) return;
    const minutes = readSetting('autolock', DEFAULTS.autolock);
    if (!minutes || minutes <= 0) return;
    state.autolockTimerId = setTimeout(function () {
      lockVault('timeout');
    }, minutes * 60 * 1000);
  }

  function clearAutolock() {
    if (state.autolockTimerId) {
      clearTimeout(state.autolockTimerId);
      state.autolockTimerId = null;
    }
  }

  function resetAutolock() {
    if (!state.unlocked) return;
    scheduleAutolock();
  }

  function lockVault(reason) {
    if (!state.unlocked) return;
    state.unlocked = false;
    clearAutolock();
    if (window.MV && MV.Auth && typeof MV.Auth.lock === 'function') {
      try { MV.Auth.lock(); } catch (e) {}
    }
    const app = $('app-shell');
    if (app) app.hidden = true;
    showLockOverlay();
    if (reason === 'timeout') toast('اتقفلت الخزنة تلقائياً', 'info');
    else if (reason === 'manual') toast('اتقفلت الخزنة', 'info');
  }

  function unlockVault() {
    hideLockOverlay();
    showAuth();
    const p1 = $('auth-password-1');
    const p2 = $('auth-password-2');
    if (p1) p1.value = '';
    if (p2) p2.value = '';
    tempMaster = null;
    tempSecond = null;
  }

  let tempMaster = null;
  let tempSecond = null;

  async function submitAuthStep1(password) {
    if (!window.MV || !MV.Auth) {
      setAuthError(1, 'auth.js لسه مش محمّل');
      return;
    }
    const btn = $('auth-submit-1');
    setBtnLoading(btn, true);
    try {
      const ok = await MV.Auth.verifyMaster(password);
      if (!ok) {
        setAuthError(1, 'كلمة السر الرئيسية غلط');
        return;
      }
      tempMaster = password;
      clearAuthErrors();
      showAuthStep(2);
    } catch (e) {
      console.error('[MV] verifyMaster error', e);
      setAuthError(1, 'حصل خطأ، حاول تاني');
    } finally {
      setBtnLoading(btn, false);
    }
  }

  async function submitAuthStep2(password) {
    if (!window.MV || !MV.Auth) {
      setAuthError(2, 'auth.js لسه مش محمّل');
      return;
    }
    if (!tempMaster) {
      showAuthStep(1);
      return;
    }
    const btn = $('auth-submit-2');
    setBtnLoading(btn, true);
    try {
      const ok = await MV.Auth.verifySecond(password);
      if (!ok) {
        setAuthError(2, 'كلمة السر الثانية غلط');
        return;
      }
      tempSecond = password;
      await MV.Auth.completeLogin(tempMaster, tempSecond);
      tempMaster = null;
      tempSecond = null;
      clearAuthErrors();
      hideLockOverlay();
      showApp();
      toast('أهلاً بيك في خزنتك', 'success');
      scheduleAutolock();
    } catch (e) {
      console.error('[MV] completeLogin error', e);
      setAuthError(2, 'حصل خطأ، حاول تاني');
    } finally {
      setBtnLoading(btn, false);
    }
  }

  function setBtnLoading(btn, loading) {
    if (!btn) return;
    btn.classList.toggle('is-loading', !!loading);
    btn.disabled = !!loading;
    const sp = btn.querySelector('.btn__spinner');
    if (sp) sp.hidden = !loading;
  }

  function togglePasswordVisibility(targetId) {
    const inp = $(targetId);
    if (!inp) return;
    const btn = document.querySelector('[data-toggle-target="' + targetId + '"]');
    const reveal = inp.type === 'password';
    inp.type = reveal ? 'text' : 'password';
    if (btn) {
      btn.setAttribute('aria-pressed', reveal ? 'true' : 'false');
      btn.classList.toggle('is-revealed', reveal);
      const use = btn.querySelector('use');
      if (use) use.setAttribute('href', reveal ? '#icon-eye-off' : '#icon-eye');
    }
    if (reveal) {
      const seconds = readSetting('visibility', DEFAULTS.visibility);
      if (state.visibilityTimers[targetId]) clearTimeout(state.visibilityTimers[targetId]);
      state.visibilityTimers[targetId] = setTimeout(function () {
        inp.type = 'password';
        if (btn) {
          btn.setAttribute('aria-pressed', 'false');
          btn.classList.remove('is-revealed');
          const use = btn.querySelector('use');
          if (use) use.setAttribute('href', '#icon-eye');
        }
        delete state.visibilityTimers[targetId];
      }, seconds * 1000);
    }
  }

  async function copyText(text, sensitive) {
    if (!text) { toast('مفيش حاجة للنسخ', 'error'); return; }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      toast('تم النسخ', 'success', 1800);
      if (sensitive) {
        if (state.clipboardTimerId) clearTimeout(state.clipboardTimerId);
        const seconds = readSetting('clipboard', DEFAULTS.clipboard);
        state.clipboardTimerId = setTimeout(function () {
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText('').catch(function () {});
            }
          } catch (e) {}
        }, seconds * 1000);
      }
    } catch (e) {
      console.error('[MV] copy failed', e);
      toast('تعذّر النسخ', 'error');
    }
  }

  function bindAuthUI() {
    const form1 = $('auth-step-1');
    const form2 = $('auth-step-2');
    const backBtn = $('auth-back-2');
    if (form1) {
      form1.addEventListener('submit', function (e) {
        e.preventDefault();
        const p = ($('auth-password-1') || {}).value || '';
        if (!p) { setAuthError(1, 'اكتب كلمة السر'); return; }
        submitAuthStep1(p);
      });
    }
    if (form2) {
      form2.addEventListener('submit', function (e) {
        e.preventDefault();
        const p = ($('auth-password-2') || {}).value || '';
        if (!p) { setAuthError(2, 'اكتب كلمة السر التانية'); return; }
        submitAuthStep2(p);
      });
    }
    if (backBtn) {
      backBtn.addEventListener('click', function () {
        tempMaster = null;
        showAuthStep(1);
      });
    }
    document.querySelectorAll('[data-toggle-target]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        togglePasswordVisibility(btn.getAttribute('data-toggle-target'));
      });
    });
    const unlockBtn = $('btn-unlock');
    if (unlockBtn) unlockBtn.addEventListener('click', unlockVault);
  }

  function bindNav() {
    document.querySelectorAll('.nav-item').forEach(function (btn) {
      btn.addEventListener('click', function () {
        navigate(btn.getAttribute('data-nav'));
      });
    });
  }

  function bindHeader() {
    const lock = $('btn-lock');
    const settings = $('btn-settings-header');
    if (lock) lock.addEventListener('click', function () { lockVault('manual'); });
    if (settings) settings.addEventListener('click', function () { navigate('settings'); });
  }

  function bindSearch() {
    const input = $('search-input');
    const clear = $('search-clear');
    if (input) {
      input.addEventListener('input', function () {
        state.searchQuery = input.value.trim();
        if (clear) clear.hidden = state.searchQuery.length === 0;
        if (window.MV && MV.Cards && typeof MV.Cards.refresh === 'function') {
          try { MV.Cards.refresh(); } catch (e) {}
        }
      });
    }
    if (clear) {
      clear.addEventListener('click', function () {
        if (input) input.value = '';
        state.searchQuery = '';
        clear.hidden = true;
        if (input) input.focus();
        if (window.MV && MV.Cards && typeof MV.Cards.refresh === 'function') {
          try { MV.Cards.refresh(); } catch (e) {}
        }
      });
    }
    const sortBtn = $('btn-sort');
    const sortLabel = $('sort-label');
    if (sortBtn && sortLabel) {
      sortLabel.textContent = SORT_LABELS[state.sortMode] || 'الأحدث';
      sortBtn.addEventListener('click', function () {
        const order = ['modified', 'name', 'created'];
        const i = order.indexOf(state.sortMode);
        state.sortMode = order[(i + 1) % order.length];
        sortLabel.textContent = SORT_LABELS[state.sortMode];
        if (window.MV && MV.Cards && typeof MV.Cards.refresh === 'function') {
          try { MV.Cards.refresh(); } catch (e) {}
        }
      });
    }
  }

  function bindFab() {
    const fab = $('fab-add');
    if (fab) fab.addEventListener('click', function () { openEditor(null); });
    const emptyBtn = $('btn-empty-add');
    if (emptyBtn) emptyBtn.addEventListener('click', function () { openEditor(null); });
  }

  function bindEditor() {
    const back = $('btn-editor-back');
    const cancel = $('btn-editor-cancel');
    const form = $('card-form');
    if (back) back.addEventListener('click', closeEditor);
    if (cancel) cancel.addEventListener('click', closeEditor);
    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (window.MV && MV.Cards && typeof MV.Cards.saveEditor === 'function') {
          Promise.resolve(MV.Cards.saveEditor()).then(function () {
            toast('تم حفظ الكارت', 'success');
            closeEditor();
            refreshAll();
          }).catch(function (err) {
            console.error('[MV] saveEditor failed', err);
            toast(err && err.message ? err.message : 'تعذّر الحفظ', 'error');
          });
        } else {
          toast('cards.js لسه مش محمّل', 'error');
        }
      });
    }
    const addCf = $('btn-add-custom-field');
    if (addCf) addCf.addEventListener('click', function () {
      if (window.MV && MV.Cards && typeof MV.Cards.addCustomField === 'function') MV.Cards.addCustomField();
    });
    const addLink = $('btn-add-link');
    if (addLink) addLink.addEventListener('click', function () {
      if (window.MV && MV.Cards && typeof MV.Cards.addLink === 'function') MV.Cards.addLink();
    });
    const addImgs = $('btn-editor-add-images');
    if (addImgs) addImgs.addEventListener('click', function () {
      if (window.MV && MV.Images && typeof MV.Images.openPicker === 'function') MV.Images.openPicker();
    });
    const pickCover = $('btn-editor-pick-cover');
    if (pickCover) pickCover.addEventListener('click', function () {
      if (window.MV && MV.Images && typeof MV.Images.openCoverPicker === 'function') MV.Images.openCoverPicker();
    });
    const removeCover = $('btn-editor-remove-cover');
    if (removeCover) removeCover.addEventListener('click', function () {
      if (window.MV && MV.Images && typeof MV.Images.removeCover === 'function') MV.Images.removeCover();
    });
  }

  function bindDetails() {
    const back = $('btn-details-back');
    const fav = $('btn-details-favorite');
    const edit = $('btn-details-edit');
    const editBottom = $('btn-details-edit-bottom');
    const del = $('btn-details-delete');
    if (back) back.addEventListener('click', function () {
      navigate(state.previousView || 'dashboard');
    });
    if (fav) fav.addEventListener('click', function () {
      if (window.MV && MV.Cards && typeof MV.Cards.toggleFavorite === 'function') {
        try { MV.Cards.toggleFavorite(state.currentCardId); } catch (e) {}
      }
    });
    if (edit) edit.addEventListener('click', function () {
      if (state.currentCardId) openEditor(state.currentCardId);
    });
    if (editBottom) editBottom.addEventListener('click', function () {
      if (state.currentCardId) openEditor(state.currentCardId);
    });
    if (del) del.addEventListener('click', function () {
      if (!state.currentCardId) return;
      confirmAction({
        title: 'حذف الكارت',
        text: 'متأكد عايز تحذف الكارت ده نهائياً؟ مش ممكن التراجع.',
        confirmText: 'احذف',
        danger: true
      }).then(function (ok) {
        if (!ok) return;
        if (window.MV && MV.Cards && typeof MV.Cards.deleteCard === 'function') {
          Promise.resolve(MV.Cards.deleteCard(state.currentCardId)).then(function () {
            toast('تم حذف الكارت', 'success');
            state.currentCardId = null;
            navigate('dashboard');
            refreshAll();
          });
        }
      });
    });
  }

  function bindCategories() {
    const add = $('btn-add-category');
    if (add) add.addEventListener('click', function () {
      if (window.MV && MV.Categories && typeof MV.Categories.openCreate === 'function') {
        MV.Categories.openCreate();
      } else if (window.MV && MV.Settings && typeof MV.Settings.openCreateCategory === 'function') {
        MV.Settings.openCreateCategory();
      } else {
        toast('إدارة الأقسام لسه مش متاحة', 'info');
      }
    });
  }

  function bindSettings() {
    const themeSel = $('setting-theme');
    if (themeSel) {
      themeSel.value = readSetting('theme', DEFAULTS.theme);
      themeSel.addEventListener('change', function () {
        applyTheme(themeSel.value);
        writeSetting('theme', themeSel.value);
      });
    }
    const autolockSel = $('setting-autolock');
    if (autolockSel) {
      autolockSel.value = String(readSetting('autolock', DEFAULTS.autolock));
      autolockSel.addEventListener('change', function () {
        writeSetting('autolock', autolockSel.value);
        resetAutolock();
      });
    }
    const visSel = $('setting-visibility');
    if (visSel) {
      visSel.value = String(readSetting('visibility', DEFAULTS.visibility));
      visSel.addEventListener('change', function () {
        writeSetting('visibility', visSel.value);
      });
    }
    const clipSel = $('setting-clipboard');
    if (clipSel) {
      clipSel.value = String(readSetting('clipboard', DEFAULTS.clipboard));
      clipSel.addEventListener('change', function () {
        writeSetting('clipboard', clipSel.value);
      });
    }
    const sortSel = $('setting-sort');
    if (sortSel) {
      sortSel.value = readSetting('sort', DEFAULTS.sort);
      sortSel.addEventListener('change', function () {
        writeSetting('sort', sortSel.value);
        state.sortMode = sortSel.value;
        const lbl = $('sort-label');
        if (lbl) lbl.textContent = SORT_LABELS[state.sortMode] || 'الأحدث';
        if (window.MV && MV.Cards && typeof MV.Cards.refresh === 'function') {
          try { MV.Cards.refresh(); } catch (e) {}
        }
      });
    }
    const btnMaster = $('btn-change-master');
    if (btnMaster) btnMaster.addEventListener('click', function () {
      if (window.MV && MV.Settings && typeof MV.Settings.openChangeMaster === 'function') {
        MV.Settings.openChangeMaster();
      } else {
        toast('settings.js لسه مش محمّل', 'error');
      }
    });
    const btnSecond = $('btn-change-second');
    if (btnSecond) btnSecond.addEventListener('click', function () {
      if (window.MV && MV.Settings && typeof MV.Settings.openChangeSecond === 'function') {
        MV.Settings.openChangeSecond();
      } else {
        toast('settings.js لسه مش محمّل', 'error');
      }
    });
    const btnClear = $('btn-clear-data');
    if (btnClear) btnClear.addEventListener('click', function () {
      confirmAction({
        title: 'حذف كل البيانات',
        text: 'هيتم حذف كل الكروت والصور والأقسام وبيانات الدخول نهائياً. العملية مش ممكن التراجع عنها. متأكد؟',
        confirmText: 'احذف كل حاجة',
        danger: true
      }).then(async function (ok) {
        if (!ok) return;
        try {
          if (window.MV && MV.DB && typeof MV.DB.clearAll === 'function') {
            await MV.DB.clearAll();
          }
          try { localStorage.clear(); } catch (e) {}
          toast('اتحذفت كل البيانات', 'success');
          setTimeout(function () { location.reload(); }, 800);
        } catch (e) {
          console.error('[MV] clear data failed', e);
          toast('تعذّر الحذف', 'error');
        }
      });
    });
    const online = $('app-online');
    if (online) online.textContent = navigator.onLine ? 'متصل' : 'غير متصل';
    window.addEventListener('online', function () { if (online) online.textContent = 'متصل'; });
    window.addEventListener('offline', function () { if (online) online.textContent = 'غير متصل'; });
    const standalone = $('app-standalone');
    if (standalone) {
      const isStand = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
      standalone.textContent = isStand ? 'مثبّت' : 'متصفح';
    }
    const version = $('app-version');
    if (version) version.textContent = '1.0.0';
  }

  function bindConfirm() {
    const ok = $('confirm-ok');
    const cancel = $('confirm-cancel');
    const root = $('confirm-root');
    if (ok) ok.addEventListener('click', function () { resolveConfirm(true); });
    if (cancel) cancel.addEventListener('click', function () { resolveConfirm(false); });
    if (root) root.addEventListener('click', function (e) {
      if (e.target === root) resolveConfirm(false);
    });
  }

  function bindModal() {
    const close = $('modal-close');
    const root = $('modal-root');
    if (close) close.addEventListener('click', closeModal);
    if (root) root.addEventListener('click', function (e) {
      if (e.target === root) closeModal();
    });
  }

  function bindGlobalActivity() {
    ['click', 'keydown', 'touchstart', 'mousemove', 'scroll'].forEach(function (ev) {
      document.addEventListener(ev, resetAutolock, { passive: true });
    });
  }

  function bindPrivacy() {
    const curtain = $('privacy-curtain');
    if (!curtain) return;
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') {
        if (state.unlocked) curtain.hidden = false;
      } else {
        if (state.unlocked) {
          curtain.hidden = true;
          resetAutolock();
        }
      }
    });
    window.addEventListener('blur', function () {
      if (state.unlocked) curtain.hidden = false;
    });
    window.addEventListener('focus', function () {
      if (state.unlocked) {
        curtain.hidden = true;
        resetAutolock();
      }
    });
  }

  function bindGlobalActions() {
    document.addEventListener('click', function (e) {
      const copyBtn = e.target.closest('[data-copy-target]');
      if (copyBtn) {
        e.preventDefault();
        const target = $(copyBtn.getAttribute('data-copy-target'));
        const sensitive = copyBtn.getAttribute('data-sensitive') === 'true';
        if (target && target.value) copyText(target.value, sensitive);
        return;
      }
    });
  }

  function bindCategoryChips() {
    if (window.MV && MV.Cards && typeof MV.Cards.renderCategoryChips === 'function') {
      try { MV.Cards.renderCategoryChips(); } catch (e) {}
    }
  }

  async function boot() {
    if (state.booted) return;
    state.booted = true;

    applyTheme(readSetting('theme', DEFAULTS.theme));
    state.sortMode = readSetting('sort', DEFAULTS.sort);

    const modules = ['Crypto', 'DB', 'Auth', 'Images', 'Cards', 'Settings'];
    const loaded = modules.filter(function (m) { return window.MV && window.MV[m]; });
    const missing = modules.filter(function (m) { return !(window.MV && window.MV[m]); });
    if (loaded.length) console.info('[MV] modules loaded:', loaded.join(', '));
    if (missing.length) console.warn('[MV] modules missing:', missing.join(', '));

    if (window.MV && MV.Crypto) {
      try {
        const ok = await MV.Crypto.selfTest();
        if (ok) console.info('[MV] crypto self-test passed');
        else console.warn('[MV] crypto self-test failed');
      } catch (e) {
        console.warn('[MV] crypto self-test error:', e);
      }
    }

    try {
      if (window.MV && MV.DB && typeof MV.DB.init === 'function') await MV.DB.init();
    } catch (e) { console.error('[MV] DB.init failed', e); }

    try {
      if (window.MV && MV.Auth && typeof MV.Auth.init === 'function') await MV.Auth.init();
    } catch (e) { console.error('[MV] Auth.init failed', e); }

    try {
      if (window.MV && MV.Settings && typeof MV.Settings.init === 'function') MV.Settings.init();
    } catch (e) { console.error('[MV] Settings.init failed', e); }

    await new Promise(function (r) { setTimeout(r, 250); });

    hideSplash();

    if (window.MV && MV.Auth && typeof MV.Auth.hasSetup === 'function') {
      try {
        const hasSetup = await MV.Auth.hasSetup();
        if (!hasSetup && typeof MV.Auth.setup === 'function') {
          await MV.Auth.setup(INITIAL_SETUP.master, INITIAL_SETUP.second);
        }
      } catch (e) {
        console.error('[MV] initial setup failed', e);
      }
    }

    showAuth();
  }

  function init() {
    bindAuthUI();
    bindNav();
    bindHeader();
    bindSearch();
    bindFab();
    bindEditor();
    bindDetails();
    bindCategories();
    bindSettings();
    bindConfirm();
    bindModal();
    bindPrivacy();
    bindGlobalActivity();
    bindGlobalActions();
    bindCategoryChips();

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        const modal = $('modal-root');
        const confirm = $('confirm-root');
        if (modal && !modal.hidden) closeModal();
        else if (confirm && !confirm.hidden) resolveConfirm(false);
      }
    });

    if (window.MV && MV.Auth && typeof MV.Auth.onLock === 'function') {
      try {
        MV.Auth.onLock(function () {
          if (!state.unlocked) return;
          state.unlocked = false;
          clearAutolock();
          const app = $('app-shell');
          if (app) app.hidden = true;
          showLockOverlay();
        });
      } catch (e) {}
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', boot, { once: true });
    } else {
      boot();
    }
  }

  window.MV = window.MV || {};
  window.MV.App = {
    state: state,
    boot: boot,
    navigate: navigate,
    openDetails: openDetails,
    openEditor: openEditor,
    closeEditor: closeEditor,
    toast: toast,
    confirm: confirmAction,
    openModal: openModal,
    closeModal: closeModal,
    lock: lockVault,
    unlock: unlockVault,
    copy: copyText,
    refreshAll: refreshAll,
    updateStorageInfo: updateStorageInfo,
    readSetting: readSetting,
    writeSetting: writeSetting,
    togglePasswordVisibility: togglePasswordVisibility,
    formatBytes: formatBytes
  };

  init();
})();
