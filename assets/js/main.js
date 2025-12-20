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

  // Ctrl+K Quick Search (global)
  const initQuickSearch = () => {
    const root = document.getElementById('quick-search');
    const input = document.getElementById('quick-search-input');
    const results = document.getElementById('quick-search-results');
    const status = document.getElementById('quick-search-status');

    if (!root || !input || !results || !status) return;

    let isOpen = false;
    let postsCache = null;
    let loading = null;
    let lastFocused = null;

    const positionModalBelowNavbar = () => {
      const modal = root.querySelector('.quick-search-modal');
      if (!modal) return;
      const navbar = document.querySelector('.navbar');
      const navbarHeight = navbar ? Math.ceil(navbar.getBoundingClientRect().height) : 0;
      modal.style.top = `${navbarHeight + 16}px`;
    };

    const setStatus = (text) => {
      status.textContent = text || '';
    };

    const escapeHtml = (s) => String(s || '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

    const ensurePostsLoaded = async () => {
      if (postsCache) return postsCache;
      if (loading) return loading;

      setStatus('Loading posts...');
      loading = fetch('/assets/search.json', { cache: 'no-store' })
        .then((r) => {
          if (!r.ok) throw new Error('Failed to load search.json');
          return r.json();
        })
        .then((data) => {
          postsCache = Array.isArray(data) ? data : [];
          return postsCache;
        })
        .catch(() => {
          postsCache = [];
          setStatus('Could not load search index.');
          return postsCache;
        })
        .finally(() => {
          loading = null;
        });

      return loading;
    };

    const scorePost = (post, tokens) => {
      const title = (post.title || '').toLowerCase();
      const excerpt = (post.excerpt || '').toLowerCase();
      const content = (post.content || '').toLowerCase();
      const tags = (post.tags || '').toLowerCase();
      const categories = (post.categories || '').toLowerCase();

      const hay = `${title} ${excerpt} ${content} ${tags} ${categories}`;
      for (const t of tokens) {
        if (!hay.includes(t)) return -1;
      }

      let score = 0;
      for (const t of tokens) {
        if (title.includes(t)) score += 6;
        if (tags.includes(t) || categories.includes(t)) score += 4;
        if (excerpt.includes(t)) score += 2;
        if (content.includes(t)) score += 1;
      }
      return score;
    };

    const renderResults = (items, query) => {
      if (!query) {
        results.innerHTML = '';
        setStatus('Type to search posts.');
        return;
      }

      if (!items || items.length === 0) {
        results.innerHTML = '';
        setStatus('No results.');
        return;
      }

      setStatus(`${items.length} result${items.length === 1 ? '' : 's'}`);
      results.innerHTML = items.map((p) => {
        const title = escapeHtml(p.title);
        const date = escapeHtml(p.date);
        const excerpt = escapeHtml(p.excerpt);
        const url = escapeHtml(p.url);
        return `
          <a class="quick-search-result" role="listitem" href="${url}">
            <div class="quick-search-result-title">${title}</div>
            <div class="quick-search-result-meta">${date}${excerpt ? ` • ${excerpt}` : ''}</div>
          </a>
        `;
      }).join('');
    };

    const doSearch = async () => {
      const q = (input.value || '').trim();
      if (!q) {
        renderResults([], '');
        return;
      }

      const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
      const posts = await ensurePostsLoaded();

      const scored = [];
      for (const post of posts) {
        const s = scorePost(post, tokens);
        if (s >= 0) scored.push({ post, s });
      }

      scored.sort((a, b) => b.s - a.s);
      const top = scored.slice(0, 12).map((x) => x.post);
      renderResults(top, q);
    };

    const open = async () => {
      if (isOpen) return;
      isOpen = true;
      lastFocused = document.activeElement;
      root.hidden = false;
      positionModalBelowNavbar();
      setStatus('Type to search posts.');
      input.value = '';
      results.innerHTML = '';
      // Load index in background so first query is fast
      ensurePostsLoaded();
      setTimeout(() => input.focus(), 0);
    };

    const close = () => {
      if (!isOpen) return;
      isOpen = false;
      root.hidden = true;
      input.value = '';
      results.innerHTML = '';
      setStatus('');
      if (lastFocused && typeof lastFocused.focus === 'function') {
        lastFocused.focus();
      }
    };

    // Close on ESC
    document.addEventListener('keydown', (e) => {
      const key = (e.key || '').toLowerCase();
      if (key === 'escape' && isOpen) {
        e.preventDefault();
        close();
      }
    }, true);

    // Open via navbar button
    const openBtn = document.getElementById('quick-search-open');
    if (openBtn) {
      openBtn.addEventListener('click', (e) => {
        e.preventDefault();
        open();
      });
    }

    // Input handlers
    let searchTimer = null;
    input.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(doSearch, 80);
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const first = results.querySelector('a.quick-search-result');
        if (first && first.getAttribute('href')) {
          window.location.href = first.getAttribute('href');
        }
      }
    });

    // Close handlers
    root.addEventListener('click', (e) => {
      const target = e.target;
      if (target && target.getAttribute && target.getAttribute('data-qs-close') !== null) {
        close();
      }
    });

    window.addEventListener('resize', () => {
      if (isOpen) positionModalBelowNavbar();
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initQuickSearch);
  } else {
    initQuickSearch();
  }
})();
