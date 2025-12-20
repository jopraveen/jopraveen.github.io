// Theme loader - Load saved theme, else follow system theme
(function() {
  const savedTheme = localStorage.getItem('siteTheme');

  const prefersDark = (() => {
    try {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (_) {
      return false;
    }
  })();

  // Map system preference to your theme names
  const systemTheme = prefersDark ? 'dark' : 'default';
  const themeToApply = savedTheme || systemTheme;

  // Apply theme immediately (before CSS renders)
  document.documentElement.setAttribute('data-theme', themeToApply);

  // Also set on body when it's available
  const applyToBody = () => {
    if (document.body) document.body.setAttribute('data-theme', themeToApply);
  };

  if (document.body) {
    applyToBody();
  } else {
    window.addEventListener('DOMContentLoaded', applyToBody);
  }
})();
