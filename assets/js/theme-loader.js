// Theme loader - Load saved theme on page load
(function() {
  // Load theme from localStorage
  const savedTheme = localStorage.getItem('siteTheme') || 'default';
  
  console.log('Loading theme:', savedTheme);
  
  // Apply theme immediately (before page renders)
  document.documentElement.setAttribute('data-theme', savedTheme);
  
  // Also set on body when it's available
  if (document.body) {
    document.body.setAttribute('data-theme', savedTheme);
  } else {
    window.addEventListener('DOMContentLoaded', function() {
      document.body.setAttribute('data-theme', savedTheme);
      console.log('Theme applied to body:', savedTheme);
    });
  }
})();
