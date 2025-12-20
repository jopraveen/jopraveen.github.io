(() => {
  // Theme switch
  const body = document.body;
  const lamp = document.getElementById("mode");

  const toggleTheme = (state) => {
    if (state === "dark") {
      localStorage.setItem("theme", "light");
      body.removeAttribute("data-theme");
    } else if (state === "light") {
      localStorage.setItem("theme", "dark");
      body.setAttribute("data-theme", "dark");
    } else {
      initTheme(state);
    }
  };

  // Only add listener if element exists
  if (lamp) {
    lamp.addEventListener("click", () =>
      toggleTheme(localStorage.getItem("theme"))
    );
  }

  // Blur the content when the menu is open
  const cbox = document.getElementById("menu-trigger");

  if (cbox) {
    cbox.addEventListener("change", function () {
      const area = document.querySelector(".wrapper");
      this.checked
        ? area.classList.add("blurry")
        : area.classList.remove("blurry");
    });
  }

  // Table of Contents functionality
  const initTOC = () => {
    const tocNav = document.getElementById('toc-nav');
    const tocSidebar = document.getElementById('toc-sidebar');
    const tocToggle = document.getElementById('toc-toggle');
    const postContainer = document.querySelector('.post-container');
    
    if (!tocNav || !tocSidebar || !tocToggle) return;

    // Generate TOC from headings
    const generateTOC = () => {
      const article = document.querySelector('.post-article .page-content');
      if (!article) return;

      const headings = article.querySelectorAll('h1, h2, h3, h4');
      if (headings.length === 0) {
        tocSidebar.style.display = 'none';
        tocToggle.style.display = 'none';
        return;
      }

      const tocList = document.createElement('ul');
      let currentLevel = 1;
      let currentList = tocList;
      const listStack = [tocList];

      headings.forEach((heading, index) => {
        const level = parseInt(heading.tagName.substring(1));
        const text = heading.textContent;
        const id = heading.id || `heading-${index}`;
        
        if (!heading.id) {
          heading.id = id;
        }

        // Handle nesting
        while (level > currentLevel) {
          const newList = document.createElement('ul');
          const lastItem = currentList.lastElementChild;
          if (lastItem) {
            lastItem.appendChild(newList);
          } else {
            currentList.appendChild(newList);
          }
          listStack.push(newList);
          currentList = newList;
          currentLevel++;
        }

        while (level < currentLevel && listStack.length > 1) {
          listStack.pop();
          currentList = listStack[listStack.length - 1];
          currentLevel--;
        }

        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = `#${id}`;
        a.textContent = text;
        a.addEventListener('click', (e) => {
          e.preventDefault();
          heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
          
          // Update active state
          tocNav.querySelectorAll('a').forEach(link => link.classList.remove('active'));
          a.classList.add('active');
          
          // Update URL hash
          history.pushState(null, null, `#${id}`);
        });
        
        li.appendChild(a);
        currentList.appendChild(li);
      });

      tocNav.appendChild(tocList);
    };

    // Toggle TOC
    let tocOpen = true;
    tocToggle.classList.add('toc-open');
    
    const toggleTOC = () => {
      tocOpen = !tocOpen;
      
      if (tocOpen) {
        tocSidebar.classList.remove('toc-hidden');
        postContainer.classList.remove('toc-closed');
        tocToggle.classList.add('toc-open');
        localStorage.setItem('tocOpen', 'true');
      } else {
        tocSidebar.classList.add('toc-hidden');
        postContainer.classList.add('toc-closed');
        tocToggle.classList.remove('toc-open');
        localStorage.setItem('tocOpen', 'false');
      }
    };

    // Restore TOC state
    const savedState = localStorage.getItem('tocOpen');
    if (savedState === 'false') {
      tocOpen = true; // Will be toggled to false
      toggleTOC();
    }

    tocToggle.addEventListener('click', toggleTOC);

    // Highlight active section on scroll
    const updateActiveSection = () => {
      const headings = document.querySelectorAll('.post-article .page-content h1, .post-article .page-content h2, .post-article .page-content h3, .post-article .page-content h4');
      const tocLinks = tocNav.querySelectorAll('a');
      
      let currentActive = null;
      
      headings.forEach((heading) => {
        const rect = heading.getBoundingClientRect();
        if (rect.top <= 150 && rect.top >= -100) {
          currentActive = heading.id;
        }
      });

      if (currentActive) {
        tocLinks.forEach(link => {
          if (link.getAttribute('href') === `#${currentActive}`) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
        });
      }
    };

    let scrollTimeout;
    window.addEventListener('scroll', () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(updateActiveSection, 50);
    });

    generateTOC();
    updateActiveSection();
  };

  // Initialize TOC when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTOC);
  } else {
    initTOC();
  }

  // Post extras: reading time, progress bar + cat, image zoom
  const initPostExtras = () => {
    const articleContent = document.querySelector('.post-article .page-content');
    if (!articleContent) return;

    // Reading time (200 WPM)
    try {
      const text = (articleContent.innerText || articleContent.textContent || '').trim();
      if (text.length > 0) {
        const words = text.split(/\s+/).filter(Boolean).length;
        const minutes = Math.max(1, Math.ceil(words / 200));
        let timeEl = document.getElementById('reading-time');
        if (!timeEl) {
          const meta = document.querySelector('.post-meta');
          if (meta) {
            const wrapper = document.createElement('span');
            wrapper.className = 'reading-time';
            wrapper.innerHTML = `• <span id="reading-time"></span> read`;
            meta.appendChild(wrapper);
            timeEl = document.getElementById('reading-time');
          }
        }
        if (timeEl) timeEl.textContent = `${minutes} min`;
      }
    } catch (_) {
      // no-op
    }

    // Progress bar + cat (injected)
    const catSrc = '/assets/img/96890-cateat.gif';
    let progressContainer = document.querySelector('.reading-progress-container');
    let progressBar = document.getElementById('reading-progress-bar');
    let progressCat = document.getElementById('progress-cat');

    if (!progressContainer) {
      progressContainer = document.createElement('div');
      progressContainer.className = 'reading-progress-container';
      progressContainer.innerHTML = `<div class="reading-progress-bar" id="reading-progress-bar"></div>`;
      document.body.appendChild(progressContainer);
      progressBar = document.getElementById('reading-progress-bar');
    }

    if (!progressCat) {
      progressCat = document.createElement('img');
      progressCat.className = 'progress-cat';
      progressCat.id = 'progress-cat';
      progressCat.alt = 'cat';
      progressCat.src = catSrc;
      document.body.appendChild(progressCat);
    }

    const positionProgressUI = () => {
      const navbar = document.querySelector('.navbar');
      const navbarHeight = navbar ? Math.ceil(navbar.getBoundingClientRect().height) : 0;

      if (progressContainer) {
        progressContainer.style.top = `${navbarHeight}px`;
      }

      if (progressCat) {
        // Place the cat on the bar line (slightly overlapping looks best)
        progressCat.style.top = `${Math.max(0, navbarHeight - 2)}px`;
      }
    };

    // Ensure correct position even after the cat image loads
    if (progressCat && !progressCat.complete) {
      progressCat.addEventListener('load', positionProgressUI, { once: true });
    }
    positionProgressUI();

    let ticking = false;
    const updateProgress = () => {
      ticking = false;

      const scrollTop = window.pageYOffset || document.documentElement.scrollTop || 0;
      const docHeight = Math.max(
        document.body.scrollHeight,
        document.documentElement.scrollHeight
      );
      const winHeight = window.innerHeight || document.documentElement.clientHeight || 0;
      const denom = Math.max(1, docHeight - winHeight);
      const percent = Math.min(1, Math.max(0, scrollTop / denom));
      const pct = Math.round(percent * 100);

      if (progressBar) progressBar.style.width = `${pct}%`;

      if (progressCat) {
        const catWidth = progressCat.getBoundingClientRect().width || 35;
        const maxX = Math.max(0, window.innerWidth - catWidth);
        const x = Math.round(percent * maxX);
        progressCat.style.transform = `translateX(${x}px)`;
      }
    };

    const requestTick = () => {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(updateProgress);
    };

    window.addEventListener('scroll', requestTick, { passive: true });
    window.addEventListener('resize', () => {
      positionProgressUI();
      requestTick();
    });
    updateProgress();

    // Image zoom lightbox (injected)
    let lightbox = document.getElementById('lightbox');
    let lightboxImg = document.getElementById('lightbox-image');
    if (!lightbox) {
      lightbox = document.createElement('div');
      lightbox.className = 'lightbox';
      lightbox.id = 'lightbox';
      lightbox.innerHTML = `
        <span class="lightbox-close">&times;</span>
        <img class="lightbox-image" id="lightbox-image" alt="">
      `;
      document.body.appendChild(lightbox);
      lightboxImg = document.getElementById('lightbox-image');
    }

    const openLightbox = (src) => {
      if (!lightbox || !lightboxImg) return;
      lightboxImg.src = src;
      lightbox.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    };

    const closeLightbox = () => {
      if (!lightbox) return;
      lightbox.style.display = 'none';
      document.body.style.overflow = '';
    };

    articleContent.querySelectorAll('img').forEach((img) => {
      img.style.cursor = 'zoom-in';
      img.addEventListener('click', () => openLightbox(img.src));
    });

    if (lightbox) {
      lightbox.addEventListener('click', (e) => {
        if (e.target === lightbox || (e.target && e.target.classList && e.target.classList.contains('lightbox-close'))) {
          closeLightbox();
        }
      });
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeLightbox();
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPostExtras);
  } else {
    initPostExtras();
  }
})();
