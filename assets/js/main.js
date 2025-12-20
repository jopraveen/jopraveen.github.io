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
})();
