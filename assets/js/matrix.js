// Matrix-style falling characters background animation
(function() {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  
  // Set canvas size
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  
  // Characters to display
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  const fontSize = 14;
  const columns = canvas.width / fontSize;
  
  // Array of drops - one per column
  const drops = [];
  for (let i = 0; i < columns; i++) {
    drops[i] = Math.random() * -100;
  }
  
  // Draw function
  function draw() {
    // Black background with opacity for trail effect
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    ctx.fillStyle = '#00ff00';
    ctx.font = fontSize + 'px "Space Mono", monospace';
    
    // Loop through drops
    for (let i = 0; i < drops.length; i++) {
      // Random character
      const text = chars[Math.floor(Math.random() * chars.length)];
      
      // Draw character
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      
      // Reset drop to top randomly after it has crossed the screen
      // or randomly with small probability
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      
      // Increment Y coordinate
      drops[i]++;
    }
  }
  
  // Update canvas size on window resize
  window.addEventListener('resize', function() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  });
  
  // Run animation at 30fps for performance
  setInterval(draw, 33);
})();
