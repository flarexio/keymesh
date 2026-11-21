// Applies the saved language and appearance before the first paint, so the
// page never flashes the wrong theme. Loaded as a same-origin classic script
// (allowed by `script-src 'self'`; no inline script, no network access).
// Mirrors src/app/core/preferences.ts; keep the two in sync.
(function () {
  var root = document.documentElement;
  var saved = {};
  try {
    var parsed = JSON.parse(localStorage.getItem('keymesh.settings.v1') || '{}');
    if (parsed && typeof parsed === 'object') saved = parsed;
  } catch (e) {
    // Storage blocked or corrupt: fall back to defaults.
  }
  var theme = saved.theme === 'light' || saved.theme === 'dark' ? saved.theme : 'system';
  if (theme === 'system') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  root.setAttribute('data-theme', theme);

  var locale = saved.locale === 'zh-TW' || saved.locale === 'en' ? saved.locale : null;
  if (!locale) {
    var langs = (navigator.languages && navigator.languages.length) ? navigator.languages : [navigator.language || 'en'];
    for (var i = 0; i < langs.length && !locale; i++) {
      if (/^zh\b/i.test(langs[i])) locale = 'zh-TW';
      else if (/^en\b/i.test(langs[i])) locale = 'en';
    }
  }
  root.setAttribute('lang', locale || 'en');
})();
