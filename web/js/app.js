/**
 * ZimaOS MCP Dashboard - Alpine.js App
 */
document.addEventListener('alpine:init', () => {

  // ── Global Store ──────────────────────────────────────────────────────
  Alpine.store('app', {
    page: 'dashboard',
    loading: false,
    toasts: [],
    authenticated: API.isLoggedIn(),

    init() {
      // Hash-based routing
      const hash = location.hash.slice(1) || 'dashboard';
      this.page = hash;
      window.addEventListener('hashchange', () => {
        this.page = location.hash.slice(1) || 'dashboard';
      });
      // Verify stored key is still valid
      if (this.authenticated) {
        API.get('/status').catch(() => { this.authenticated = false; });
      }
    },

    navigate(page) {
      location.hash = page;
    },

    toast(msg, type = 'ok') {
      const id = Date.now();
      this.toasts.push({ id, msg, type });
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 3000);
    },

    logout() {
      API.logout();
    },
  });

  // ── Login Page ───────────────────────────────────────────────────────
  Alpine.data('loginPage', () => ({
    apiKey: '',
    error: '',
    loading: false,

    async login() {
      if (!this.apiKey.trim()) return;
      this.loading = true;
      this.error = '';
      try {
        const ok = await API.authenticate(this.apiKey.trim());
        if (ok) {
          Alpine.store('app').authenticated = true;
        } else {
          this.error = 'Invalid API key';
        }
      } catch (e) {
        this.error = 'Connection failed';
      } finally {
        this.loading = false;
      }
    },
  }));

  // ── Console Page ─────────────────────────────────────────────────────
  Alpine.data('consolePage', () => ({
    templates: [],
    filter: '',
    running: null,
    results: null,
    resultTitle: '',
    // Interactive input
    showInput: false,
    inputTemplate: null,
    inputValue: '',
    // Icon mapping (simple text icons)
    iconMap: {
      'heart': '\u2764', 'box': '\u25A1', 'globe': '\u25CE', 'database': '\u25A3',
      'grid': '\u25A6', 'shield': '\u25C6', 'download': '\u21E9', 'activity': '\u223F',
      'file-text': '\u2261', 'share': '\u2194', 'clock': '\u23F0', 'terminal': '\u276F',
      'wifi': '\u29D7', 'search': '\u2315', 'link': '\u26D3', 'layers': '\u2630',
      'package': '\u2610', 'refresh-cw': '\u21BB', 'trash': '\u2717', 'bell': '\u25D4',
    },

    async init() {
      try {
        const data = await API.templates();
        this.templates = data.templates || [];
      } catch (e) { console.error(e); }
    },

    get categories() {
      return [...new Set(this.templates.map(t => t.category))].sort();
    },

    get filteredTemplates() {
      if (!this.filter) return this.templates;
      return this.templates.filter(t => t.category === this.filter);
    },

    // Container selection support
    showContainerSelect: false,
    containerList: [],
    containerLoading: false,

    async runTemplate(tpl) {
      // Container Logs: fetch container list first, then show select
      if (tpl.id === 'container-logs') {
        this.inputTemplate = tpl;
        this.containerLoading = true;
        this.showContainerSelect = true;
        this.containerList = [];
        try {
          const data = await API.testTool('docker_ps', { all: true });
          const result = data.result || data;
          const containers = result?.data?.containers || [];
          this.containerList = containers.map(c => ({
            name: c.Names || c.Name || '',
            status: c.Status || c.State || '',
            image: c.Image || '',
          }));
        } catch (e) {
          this.containerList = [];
        } finally {
          this.containerLoading = false;
        }
        return;
      }

      // Other interactive templates need text input
      if (tpl.interactive && tpl.follow_up) {
        this.inputTemplate = tpl;
        this.inputValue = '';
        this.showInput = true;
        return;
      }

      this.running = tpl.id;
      this.resultTitle = tpl.name;
      this.results = null;
      try {
        const data = await API.runTemplate(tpl.id);
        this.results = data.results || [];
      } catch (e) {
        this.results = [{ tool: 'error', result: { success: false, error: e.message } }];
      } finally {
        this.running = null;
      }
    },

    async selectContainer(name) {
      this.showContainerSelect = false;
      this.running = 'container-logs';
      this.resultTitle = `Logs: ${name}`;
      this.results = null;
      try {
        const data = await API.runTemplate('container-logs', { container: name });
        this.results = data.results || [];
      } catch (e) {
        this.results = [{ tool: 'error', result: { success: false, error: e.message } }];
      } finally {
        this.running = null;
      }
    },

    async submitInput() {
      if (!this.inputValue.trim() || !this.inputTemplate) return;
      const tpl = this.inputTemplate;
      this.showInput = false;
      this.running = tpl.id;
      this.resultTitle = tpl.name;
      this.results = null;

      const body = {};
      body[tpl.follow_up.field] = this.inputValue.trim();

      try {
        const data = await API.runTemplate(tpl.id, body);
        this.results = data.results || [];
      } catch (e) {
        this.results = [{ tool: 'error', result: { success: false, error: e.message } }];
      } finally {
        this.running = null;
        this.inputValue = '';
      }
    },

    formatResult(result) {
      if (!result) return '';
      // Show data nicely if available
      if (result.data) return JSON.stringify(result.data, null, 2);
      return JSON.stringify(result, null, 2);
    },

    async copyResults() {
      if (!this.results) return;
      try {
        const text = this.results.map(r =>
          `--- ${r.tool} ---\n${this.formatResult(r.result)}`
        ).join('\n\n');
        await navigator.clipboard.writeText(text);
        Alpine.store('app').toast('Copied to clipboard');
      } catch (e) {
        Alpine.store('app').toast('Copy failed', 'error');
      }
    },
  }));

  // ── Dashboard Page ────────────────────────────────────────────────────
  Alpine.data('dashboard', () => ({
    status: null,
    audit: [],
    interval: null,
    error: '',

    async init() {
      await this.refresh();
      this.interval = setInterval(() => this.refresh(), 10000);
    },

    destroy() {
      if (this.interval) clearInterval(this.interval);
    },

    async refresh() {
      try {
        this.status = await API.status();
      } catch (e) {
        this.error = 'Failed to load status: ' + e.message;
        console.error('Status refresh failed:', e);
      }
      try {
        const auditData = await API.audit({ limit: 10 });
        this.audit = auditData.entries || [];
      } catch (e) {
        console.error('Audit refresh failed:', e);
      }
      if (this.status) this.error = '';
    },

    meterClass(pct) {
      if (pct >= 90) return 'error';
      if (pct >= 70) return 'warn';
      return 'ok';
    },
  }));

  // ── Skills Page ───────────────────────────────────────────────────────
  Alpine.data('skillsPage', () => ({
    skills: [],
    tab: 'installed',  // 'installed' or 'marketplace'
    showInstall: false,
    gitUrl: '',
    skillName: '',
    installing: false,
    // Marketplace
    marketplace: [],
    marketplaceLoading: false,
    marketplaceRegistry: '',
    // Skill detail
    showDetail: false,
    detailSkill: null,
    detailContent: '',
    _interval: null,

    async init() {
      await this.refresh();
      this._interval = setInterval(() => this.refresh(), 30000);
    },

    destroy() { if (this._interval) clearInterval(this._interval); },

    async refresh() {
      try {
        const data = await API.skills();
        this.skills = data.skills || [];
      } catch (e) { console.error(e); }
    },

    async loadMarketplace() {
      if (this.marketplace.length > 0) return;
      this.marketplaceLoading = true;
      try {
        const data = await API.marketplace();
        if (data.success) {
          this.marketplace = data.skills || [];
          this.marketplaceRegistry = data.registry || '';
        } else {
          Alpine.store('app').toast(data.error || 'Failed to load marketplace', 'error');
        }
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      } finally {
        this.marketplaceLoading = false;
      }
    },

    async installFromMarketplace(skillName) {
      this.installing = true;
      try {
        const result = await API.installFromMarketplace(skillName);
        if (result.success) {
          Alpine.store('app').toast(`"${skillName}" installed from marketplace`);
          // Update installed state in marketplace list
          const item = this.marketplace.find(s => s.name === skillName);
          if (item) item.installed = true;
          await this.refresh();
        } else {
          Alpine.store('app').toast(result.error || 'Install failed', 'error');
        }
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      } finally {
        this.installing = false;
      }
    },

    async install() {
      if (!this.gitUrl) return;
      this.installing = true;
      try {
        const result = await API.installSkill({
          git_url: this.gitUrl,
          name: this.skillName || undefined,
        });
        if (result.success) {
          Alpine.store('app').toast('Skill installed successfully');
          this.showInstall = false;
          this.gitUrl = '';
          this.skillName = '';
          await this.refresh();
        } else {
          Alpine.store('app').toast(result.error || 'Install failed', 'error');
        }
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      } finally {
        this.installing = false;
      }
    },

    async toggle(skill) {
      try {
        await API.toggleSkill(skill.name, !skill.active);
        skill.active = !skill.active;
        Alpine.store('app').toast(`${skill.name} ${skill.active ? 'enabled' : 'disabled'}`);
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      }
    },

    async remove(skill) {
      if (!confirm(`Uninstall "${skill.name}"?`)) return;
      try {
        await API.deleteSkill(skill.name);
        Alpine.store('app').toast(`${skill.name} uninstalled`);
        await this.refresh();
        // Update marketplace installed state
        const item = this.marketplace.find(s => s.name === skill.name);
        if (item) item.installed = false;
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      }
    },

    async viewDetail(skill) {
      this.detailSkill = skill;
      this.detailContent = 'Loading...';
      this.showDetail = true;
      try {
        const data = await API.skillContent(skill.name);
        this.detailContent = data.success ? data.content : data.error;
      } catch (e) {
        this.detailContent = 'Failed to load content';
      }
    },

    async handleDrop(e) {
      e.preventDefault();
      const file = e.dataTransfer?.files[0];
      if (!file || (!file.name.endsWith('.py') && !file.name.endsWith('.md'))) {
        Alpine.store('app').toast('Please drop a .py or .md file', 'error');
        return;
      }
      try {
        const result = await API.uploadSkill(file);
        if (result.success) {
          Alpine.store('app').toast(`Skill "${file.name}" uploaded`);
          await this.refresh();
        } else {
          Alpine.store('app').toast(result.error, 'error');
        }
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      }
    },
  }));

  // ── Tools Page ────────────────────────────────────────────────────────
  Alpine.data('toolsPage', () => ({
    tools: [],
    selected: null,
    params: {},
    result: null,
    testing: false,
    search: '',
    history: [],  // [{tool, params, result, timestamp}]

    async init() {
      try {
        const data = await API.tools();
        this.tools = data.tools || [];
      } catch (e) { console.error(e); }
    },

    get filteredTools() {
      if (!this.search) return this.tools;
      const q = this.search.toLowerCase();
      return this.tools.filter(t =>
        t.name.toLowerCase().includes(q) ||
        (t.description || '').toLowerCase().includes(q)
      );
    },

    selectTool(tool) {
      this.selected = tool;
      this.params = {};
      this.result = null;
      // Pre-fill params with defaults
      if (tool.parameters) {
        for (const [k, v] of Object.entries(tool.parameters)) {
          if (v.default !== undefined && v.default !== 'inspect.Parameter.empty') {
            try { this.params[k] = JSON.parse(v.default.replace(/'/g, '"')); }
            catch { this.params[k] = v.default.replace(/^'|'$/g, ''); }
          } else {
            this.params[k] = '';
          }
        }
      }
    },

    async test() {
      if (!this.selected) return;
      this.testing = true;
      this.result = null;
      try {
        // Clean params: remove empty strings, parse numbers/booleans
        const clean = {};
        for (const [k, v] of Object.entries(this.params)) {
          if (v === '' || v === undefined) continue;
          if (v === 'true') clean[k] = true;
          else if (v === 'false') clean[k] = false;
          else if (!isNaN(v) && v !== '') clean[k] = Number(v);
          else clean[k] = v;
        }
        this.result = await API.testTool(this.selected.name, clean);
        // Save to history (keep last 20)
        this.history.unshift({
          tool: this.selected.name,
          params: { ...clean },
          result: this.result,
          timestamp: new Date().toLocaleTimeString(),
        });
        if (this.history.length > 20) this.history = this.history.slice(0, 20);
      } catch (e) {
        this.result = { error: e.message };
      } finally {
        this.testing = false;
      }
    },

    async copyResult() {
      if (!this.result) return;
      try {
        await navigator.clipboard.writeText(JSON.stringify(this.result, null, 2));
        Alpine.store('app').toast('Copied to clipboard');
      } catch (e) {
        Alpine.store('app').toast('Copy failed', 'error');
      }
    },
  }));

  // ── Audit Page ────────────────────────────────────────────────────────
  Alpine.data('auditPage', () => ({
    entries: [],
    total: 0,
    offset: 0,
    limit: 50,
    search: '',
    _interval: null,

    async init() {
      await this.refresh();
      this._interval = setInterval(() => this.refresh(), 15000);
    },

    destroy() { if (this._interval) clearInterval(this._interval); },

    async refresh() {
      try {
        const data = await API.audit({
          limit: this.limit,
          offset: this.offset,
          q: this.search,
        });
        this.entries = data.entries || [];
        this.total = data.total || 0;
      } catch (e) { console.error(e); }
    },

    async nextPage() {
      if (this.offset + this.limit < this.total) {
        this.offset += this.limit;
        await this.refresh();
      }
    },

    async prevPage() {
      if (this.offset > 0) {
        this.offset = Math.max(0, this.offset - this.limit);
        await this.refresh();
      }
    },

    async doSearch() {
      this.offset = 0;
      await this.refresh();
    },
  }));

  // ── Settings Page ─────────────────────────────────────────────────────
  Alpine.data('settingsPage', () => ({
    config: {},
    saving: false,

    async init() {
      try { this.config = await API.config(); }
      catch (e) { console.error(e); }
    },

    async save() {
      this.saving = true;
      try {
        const result = await API.updateConfig(this.config);
        if (result.success) {
          Alpine.store('app').toast('Configuration saved. Restart to apply.');
        } else {
          Alpine.store('app').toast(result.error || 'Save failed', 'error');
        }
      } catch (e) {
        Alpine.store('app').toast(e.message, 'error');
      } finally {
        this.saving = false;
      }
    },
  }));

});
