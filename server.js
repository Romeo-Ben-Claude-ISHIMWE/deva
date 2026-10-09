const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const envPath = path.join(root, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  });
}
const port = Number(process.env.PORT || 8080);
const adminUsername = process.env.ADMIN_USERNAME || '';
const passwordHash = process.env.ADMIN_PASSWORD_HASH || '';
const sessionSecret = process.env.SESSION_SECRET || '';
const sessions = new Map();
const attempts = new Map();
const maxBodySize = 12 * 1024;
const sessionDuration = 8 * 60 * 60 * 1000;

function send(response, status, body, type = 'application/json; charset=utf-8', headers = {}) {
  response.writeHead(status, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', ...headers });
  response.end(body);
}

function json(response, status, body, headers = {}) {
  send(response, status, JSON.stringify(body), 'application/json; charset=utf-8', headers);
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((part) => {
    const separator = part.indexOf('=');
    return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
  }));
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > maxBodySize) reject(new Error('Request too large'));
    });
    request.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); }
    });
    request.on('error', reject);
  });
}

function parseHash(value) {
  const parts = value.split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return null;
  return { N: Number(parts[1]), salt: parts[2], digest: parts[3] };
}

function verifyPassword(password, encodedHash) {
  const parsed = parseHash(encodedHash);
  if (!parsed || !Number.isSafeInteger(parsed.N) || parsed.N < 16384) return false;
  const derived = crypto.scryptSync(password, parsed.salt, 64, { N: parsed.N }).toString('base64url');
  const expected = Buffer.from(parsed.digest);
  const actual = Buffer.from(derived);
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function isAuthenticated(request) {
  const token = parseCookies(request).deva_admin_session;
  const sessionKey = token && crypto.createHmac('sha256', sessionSecret).update(token).digest('base64url');
  const session = sessionKey && sessions.get(sessionKey);
  if (!session || session.expiresAt < Date.now()) {
    if (sessionKey) sessions.delete(sessionKey);
    return false;
  }
  return true;
}

function clientKey(request) {
  return request.socket.remoteAddress || 'unknown';
}

function isRateLimited(request) {
  const now = Date.now();
  const record = attempts.get(clientKey(request));
  if (!record || record.resetAt < now) {
    attempts.set(clientKey(request), { count: 0, resetAt: now + 15 * 60 * 1000 });
    return false;
  }
  return record.count >= 10;
}

function recordFailure(request) {
  const key = clientKey(request);
  const record = attempts.get(key) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
  record.count += 1;
  attempts.set(key, record);
}

function serveStatic(request, response, pathname) {
  let relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  if (relative.endsWith('/')) relative += 'index.html';
  const filePath = path.resolve(root, relative);
  if (!filePath.startsWith(root + path.sep)) return send(response, 403, 'Forbidden', 'text/plain; charset=utf-8');
  fs.stat(filePath, (error, stats) => {
    if (error || !stats.isFile()) return send(response, 404, 'Not found', 'text/plain; charset=utf-8');
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.woff2': 'font/woff2' };
    send(response, 200, fs.readFileSync(filePath), types[path.extname(filePath).toLowerCase()] || 'application/octet-stream');
  });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (request.method === 'POST' && url.pathname === '/api/admin/login') {
    if (!adminUsername || !passwordHash || !sessionSecret) return json(response, 503, { error: 'Admin authentication is not configured.' });
    if (isRateLimited(request)) return json(response, 429, { error: 'Too many attempts. Try again later.' });
    try {
      const body = await parseBody(request);
      const valid = typeof body.username === 'string' && typeof body.password === 'string' && body.username === adminUsername && verifyPassword(body.password, passwordHash);
      if (!valid) {
        recordFailure(request);
        return json(response, 401, { error: 'Invalid email or password.' });
      }
      const token = crypto.randomBytes(32).toString('base64url');
      const sessionKey = crypto.createHmac('sha256', sessionSecret).update(token).digest('base64url');
      sessions.set(sessionKey, { expiresAt: Date.now() + sessionDuration });
      return json(response, 200, { ok: true }, { 'Set-Cookie': `deva_admin_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionDuration / 1000}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}` });
    } catch (error) {
      return json(response, 400, { error: error.message });
    }
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/session') return json(response, 200, { authenticated: isAuthenticated(request) });
  if (request.method === 'POST' && url.pathname === '/api/admin/logout') {
    const token = parseCookies(request).deva_admin_session;
    if (token) sessions.delete(crypto.createHmac('sha256', sessionSecret).update(token).digest('base64url'));
    return json(response, 200, { ok: true }, { 'Set-Cookie': 'deva_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }
  if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
    if (url.pathname !== '/admin/' && url.pathname !== '/admin/index.html') return send(response, 404, 'Not found', 'text/plain; charset=utf-8');
    return serveStatic(request, response, '/admin/index.html');
  }
  return serveStatic(request, response, url.pathname);
});

server.listen(port, () => console.log(`Deva site running at http://localhost:${port}`));