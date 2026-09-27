const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// PROXY: CSRF
app.get('/proxy/auth/csrf', async (req, res) => {
  try {
    const data = await fetchJson('https://www.esimoa.com/api/auth/csrf');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PROXY: Login
app.post('/proxy/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const csrfRaw = await fetchRaw('https://www.esimoa.com/api/auth/csrf');
    let csrfData;
    try { csrfData = JSON.parse(csrfRaw.body); } catch { throw new Error('CSRF parse failed'); }
    const csrfToken = csrfData.csrfToken;
    const csrfCookies = extractCookies(csrfRaw.headers);

    const formBody = new URLSearchParams({
      csrfToken,
      email,
      password,
      callbackUrl: 'https://www.esimoa.com/en/call',
      json: 'true'
    }).toString();

    const loginRaw = await fetchRaw('https://www.esimoa.com/api/auth/callback/credentials', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': csrfCookies
      },
      body: formBody
    });

    const cookies = mergeCookies(csrfCookies, extractCookies(loginRaw.headers));

    const sessionRaw = await fetchRaw('https://www.esimoa.com/api/auth/session', {
      headers: { Cookie: cookies }
    });

    let session;
    try { session = JSON.parse(sessionRaw.body); } catch { throw new Error('Session parse failed'); }

    if (!session.accessToken) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    res.json(session);
  } catch (e) {
    console.error('Login proxy error:', e);
    res.status(500).json({ error: e.message || 'Login failed' });
  }
});

// PROXY: GraphQL
app.post('/proxy/graphql', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const raw = await fetchRaw('https://api.esimoa.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': auth
      },
      body: JSON.stringify(req.body)
    });
    try {
      res.json(JSON.parse(raw.body));
    } catch {
      res.status(500).json({ error: 'GraphQL parse failed', raw: raw.body });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log('esimoa-call-clone running on port ' + PORT);
});

function fetchRaw(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const u = new URL(url);
    const opts = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };
    const req = lib.request(opts, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function fetchJson(url, options = {}) {
  return fetchRaw(url, options).then(r => {
    try { return JSON.parse(r.body); }
    catch { return { _raw: r.body }; }
  });
}

function extractCookies(headers) {
  if (!headers) return '';
  const setCookie = headers['set-cookie'];
  if (!setCookie) return '';
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  return arr.map(c => c.split(';')[0]).join('; ');
}

function mergeCookies() {
  const map = {};
  for (let i = 0; i < arguments.length; i++) {
    const str = arguments[i];
    if (!str) continue;
    str.split(';').forEach(part => {
      const idx = part.trim().indexOf('=');
      if (idx > 0) {
        const k = part.trim().substring(0, idx);
        const v = part.trim().substring(idx + 1);
        map[k] = v;
      }
    });
  }
  return Object.keys(map).map(k => k + '=' + map[k]).join('; ');
}
