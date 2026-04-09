/**
 * ZimaOS MCP Dashboard - API Client
 */
const API = {
  base: '/api',

  _authHeaders() {
    const key = localStorage.getItem('mcp_api_key') || '';
    return { 'X-API-Key': key };
  },

  async get(path) {
    const res = await fetch(this.base + path, { headers: this._authHeaders() });
    if (res.status === 401) { this._onUnauth(); throw new Error('Unauthorized'); }
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(this.base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this._authHeaders() },
      body: JSON.stringify(body),
    });
    if (res.status === 401) { this._onUnauth(); throw new Error('Unauthorized'); }
    if (!res.ok) { const body = await res.json().catch(() => ({})); return { success: false, error: body.error || `API error ${res.status}` }; }
    return res.json();
  },

  async put(path, body) {
    const res = await fetch(this.base + path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...this._authHeaders() },
      body: JSON.stringify(body),
    });
    if (res.status === 401) { this._onUnauth(); throw new Error('Unauthorized'); }
    if (!res.ok) { const body = await res.json().catch(() => ({})); return { success: false, error: body.error || `API error ${res.status}` }; }
    return res.json();
  },

  async del(path) {
    const res = await fetch(this.base + path, {
      method: 'DELETE',
      headers: this._authHeaders(),
    });
    if (res.status === 401) { this._onUnauth(); throw new Error('Unauthorized'); }
    if (!res.ok) { const body = await res.json().catch(() => ({})); return { success: false, error: body.error || `API error ${res.status}` }; }
    return res.json();
  },

  async upload(path, file) {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(this.base + path, {
      method: 'POST',
      headers: this._authHeaders(),
      body: form,
    });
    if (res.status === 401) { this._onUnauth(); throw new Error('Unauthorized'); }
    if (!res.ok) { const body = await res.json().catch(() => ({})); return { success: false, error: body.error || `API error ${res.status}` }; }
    return res.json();
  },

  async authenticate(apiKey) {
    const res = await fetch(this.base + '/auth', {
      method: 'POST',
      headers: { 'X-API-Key': apiKey },
    });
    const data = await res.json();
    if (data.authenticated) {
      localStorage.setItem('mcp_api_key', apiKey);
      return true;
    }
    return false;
  },

  logout() {
    localStorage.removeItem('mcp_api_key');
    location.reload();
  },

  isLoggedIn() {
    return !!localStorage.getItem('mcp_api_key');
  },

  _onUnauth() {
    localStorage.removeItem('mcp_api_key');
    if (typeof Alpine !== 'undefined' && Alpine.store('app')) {
      Alpine.store('app').authenticated = false;
    }
  },

  // Convenience methods
  status: ()         => API.get('/status'),
  tools: ()          => API.get('/tools'),
  testTool: (n, p)   => API.post(`/tools/${n}/test`, p),
  marketplace: ()    => API.get('/marketplace'),
  skills: ()         => API.get('/skills'),
  installSkill: (d)  => API.post('/skills/install', d),
  installFromMarketplace: (n) => API.post('/skills/install', { marketplace: true, name: n }),
  uploadSkill: (f)   => API.upload('/skills/install', f),
  toggleSkill: (n,a) => API.post(`/skills/${n}/toggle`, { active: a }),
  deleteSkill: (n)   => API.del(`/skills/${n}`),
  skillContent: (n)  => API.get(`/skills/${n}/content`),
  audit: (p)         => API.get(`/audit?limit=${p?.limit||50}&offset=${p?.offset||0}&q=${p?.q||''}`),
  config: ()         => API.get('/config'),
  updateConfig: (d)  => API.put('/config', d),
  templates: ()      => API.get('/templates'),
  runTemplate: (id, body) => API.post(`/templates/${id}/run`, body || {}),
};
