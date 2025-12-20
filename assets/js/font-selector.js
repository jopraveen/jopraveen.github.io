// Font Selector
console.log('=== FONT SELECTOR JS FILE LOADED ===');

(function() {
  console.log('Font selector IIFE started');
  
  function initFontSelector() {
    console.log('initFontSelector called');
    
    var fontOptions = document.querySelectorAll('.font-option');
    console.log('Found font options:', fontOptions.length);
    
    if (fontOptions.length === 0) {
      console.error('No font options found! Trying again in 100ms...');
      setTimeout(initFontSelector, 100);
      return;
    }
    
    var savedFont = localStorage.getItem('siteFont') || 'JetBrains Mono';
    console.log('Saved font:', savedFont);
    
    // Mark active font
    fontOptions.forEach(function(option) {
      var fontName = option.getAttribute('data-font');
      console.log('Processing option:', fontName);
      
      if (fontName === savedFont) {
        option.classList.add('active');
      }
      
      // Add click handler
      option.onclick = function(e) {
        console.log('CLICKED:', fontName);
        
        var selectedFont = this.getAttribute('data-font');
        
        // Remove active from all
        fontOptions.forEach(function(opt) {
          opt.classList.remove('active');
        });
        
        // Add active to this
        this.classList.add('active');
        
        // Save to localStorage
        localStorage.setItem('siteFont', selectedFont);
        console.log('Saved to localStorage:', selectedFont);
        
        // Apply font everywhere
        var fontString = "'" + selectedFont + "', monospace";
        
        document.body.style.fontFamily = fontString;
        document.documentElement.style.fontFamily = fontString;
        
        // Update all elements
        var all = document.querySelectorAll('*');
        for (var i = 0; i < all.length; i++) {
          all[i].style.fontFamily = fontString;
        }
        
        console.log('Applied font:', selectedFont);
        
        return false;
      };
    });
    
    console.log('Font selector ready');
  }
  
  // Try multiple ways to ensure it runs
  if (document.readyState === 'loading') {
    console.log('Document still loading, waiting for DOMContentLoaded');
    document.addEventListener('DOMContentLoaded', initFontSelector);
  } else if (document.readyState === 'interactive') {
    console.log('Document interactive, initializing now');
    initFontSelector();
  } else {
    console.log('Document complete, initializing immediately');
    initFontSelector();
  }
})();

console.log('=== FONT SELECTOR SETUP COMPLETE ===');
