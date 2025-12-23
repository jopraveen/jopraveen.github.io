/* Lightweight canvas snow effect
 * - Respects prefers-reduced-motion
 * - Scoped to months via data attributes
 * - Modest particle count for performance
 */
(function () {
  // Obtain config from the script tag's data attributes
  var currentScript = document.currentScript;
  var enabledAttr = currentScript && currentScript.getAttribute('data-enabled');
  var monthsAttr = currentScript && currentScript.getAttribute('data-months');
  var densityAttr = currentScript && currentScript.getAttribute('data-density');

  // Respect reduced motion
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Month gating (defaults to December)
  var months = (monthsAttr && monthsAttr.length)
    ? monthsAttr.split(',').map(function (m) { return parseInt(m, 10); }).filter(function (n) { return !isNaN(n); })
    : [12];
  var now = new Date();
  var month = now.getMonth() + 1; // 1-12

  // Density (approximate target count)
  var baseDensity = densityAttr ? parseInt(densityAttr, 10) : 80;
  if (isNaN(baseDensity) || baseDensity < 10) baseDensity = 60;
  if (baseDensity > 200) baseDensity = 200;

  // Canvas and state
  var canvas = null;
  var ctx = null;
  var width = 0, height = 0, flakes = [], running = false, started = false;

  function rand(min, max) { return Math.random() * (max - min) + min; }

  function shouldRun() {
    var siteEnabled = (enabledAttr === null) ? false : String(enabledAttr).toLowerCase() === 'true';
    var userDisabled = false;
    var userEnabled = false;
    try {
      userDisabled = localStorage.getItem('snowDisabled') === 'true';
      userEnabled = localStorage.getItem('snowEnabled') === 'true';
    } catch (e) {}

    if (reduceMotion) return false;
    if (months.indexOf(month) === -1) return false;
    var effectiveEnabled = userEnabled || siteEnabled;
    if (!effectiveEnabled) return false;
    if (userDisabled) return false;
    return true;
  }

  function makeFlake(spawnTop) {
    var size = rand(0.8, 2.2);
    return {
      x: rand(0, width),
      y: spawnTop ? rand(-height, 0) : rand(0, height),
      r: size,
      d: rand(0.3, 0.8),
      w: rand(0.2, 0.8),
      a: rand(0, Math.PI * 2)
    };
  }

  function resize() {
    if (!canvas) return;
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    var target = Math.max(20, Math.min(200, Math.round((width * height) / 20000)));
    target = Math.round((target + baseDensity) / 2);
    if (flakes.length < target) {
      for (var i = flakes.length; i < target; i++) {
        flakes.push(makeFlake(true));
      }
    } else if (flakes.length > target) {
      flakes.length = target;
    }
  }

  function step() {
    if (!running || !ctx) return;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = 'rgba(255,255,255,0.9)';
    for (var i = 0; i < flakes.length; i++) {
      var f = flakes[i];
      f.y += f.d;
      f.a += f.w * 0.01;
      f.x += Math.sin(f.a) * 0.3;

      if (f.y > height + 2) {
        f.y = -2;
        f.x = rand(0, width);
        f.d = rand(0.3, 0.8);
        f.w = rand(0.2, 0.8);
        f.r = rand(0.8, 2.2);
      }
      if (f.x < -2) f.x = width + 2;
      if (f.x > width + 2) f.x = -2;

      ctx.beginPath();
      ctx.arc(f.x, f.y, f.r, 0, Math.PI * 2);
      ctx.closePath();
      ctx.fill();
    }
    requestAnimationFrame(step);
  }

  function start() {
    if (started || !shouldRun()) return;
    canvas = document.createElement('canvas');
    canvas.className = 'snow-canvas';
    ctx = canvas.getContext('2d');
    flakes = [];
    running = true;
    started = true;
    document.body.appendChild(canvas);
    resize();
    requestAnimationFrame(step);
  }

  function stop() {
    if (!started) return;
    running = false;
    try { if (canvas) canvas.remove(); } catch (e) {}
    canvas = null;
    ctx = null;
    flakes = [];
    started = false;
  }

  // Initial run if conditions met
  start();

  // Lifecycle
  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', function () {
    running = !document.hidden && started;
    if (running) requestAnimationFrame(step);
  });

  // React to settings changes across tabs or after toggle
  window.addEventListener('storage', function (ev) {
    if (ev.key === 'snowDisabled' || ev.key === 'snowEnabled') {
      if (shouldRun()) start(); else stop();
    }
  });
})();
