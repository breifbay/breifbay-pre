// server.js - BriefBay Pre-Release Early Access Portal Server (Hardened & Protected)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { syncUserToBriefBay, updateUserVipStatus, deleteUserFromBriefBay, syncAllUsers } = require('./sync-db.js');

// -------------------------------------------------------------
// ENVIRONMENT LOADER (.env)
// -------------------------------------------------------------
function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx > -1) {
        const key = trimmed.slice(0, idx).trim();
        const val = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
        if (!process.env[key]) {
          process.env[key] = val;
        }
      }
    }
  }
}
loadEnv();

const PORT = parseInt(process.env.PORT, 10) || 4000;
const DATA_FILE = path.join(__dirname, 'data', 'early_access_users.json');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;

// Admin Credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'briefbayadmin2027';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'briefbay_secret_key_2027';

// Active Admin Sessions: token -> { createdAt, expiresAt }
const adminSessions = new Map();

// -------------------------------------------------------------
// RATE LIMITING & SECURITY STORES
// -------------------------------------------------------------
const rateLimits = {
  ipRequests: new Map(), // ip -> { count, resetTime }
  registrations: new Map(), // ip -> { count, resetTime }
  loginAttempts: new Map() // ip -> { count, lockedUntil }
};

// Clean rate limits every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimits.ipRequests.entries()) {
    if (now > data.resetTime) rateLimits.ipRequests.delete(ip);
  }
  for (const [ip, data] of rateLimits.registrations.entries()) {
    if (now > data.resetTime) rateLimits.registrations.delete(ip);
  }
  for (const [ip, data] of rateLimits.loginAttempts.entries()) {
    if (now > data.lockedUntil) rateLimits.loginAttempts.delete(ip);
  }
  // Clean expired admin sessions
  for (const [token, session] of adminSessions.entries()) {
    if (now > session.expiresAt) adminSessions.delete(token);
  }
}, 10 * 60 * 1000);

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || '127.0.0.1';
}

function checkRateLimit(ip, type, max, windowMs) {
  const now = Date.now();
  const map = rateLimits[type];
  if (!map) return true;

  const record = map.get(ip);
  if (!record || now > (record.resetTime || record.lockedUntil)) {
    map.set(ip, { count: 1, resetTime: now + windowMs, lockedUntil: 0 });
    return true;
  }

  if (record.count >= max) {
    if (type === 'loginAttempts') {
      record.lockedUntil = now + (15 * 60 * 1000); // 15 min lock
    }
    return false;
  }

  record.count++;
  return true;
}

// Ensure data folder exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

function loadUsers() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading users:', err);
  }
  return [];
}

function saveUsers(users) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving users:', err);
  }
}

function getStats(users) {
  const clients = users.filter(u => u.role === 'CLIENT');
  const freelancers = users.filter(u => u.role === 'FREELANCER');

  const clientVipCount = clients.filter(u => u.isFirst15).length;
  const freelancerVipCount = freelancers.filter(u => u.isFirst15).length;

  return {
    total: users.length,
    clientsTotal: clients.length,
    freelancersTotal: freelancers.length,
    clientVipClaimed: clientVipCount,
    clientVipRemaining: Math.max(0, 15 - clientVipCount),
    freelancerVipClaimed: freelancerVipCount,
    freelancerVipRemaining: Math.max(0, 15 - freelancerVipCount),
    maxVipPerCategory: 15
  };
}

// Timing-safe string compare to prevent timing side-channel attacks
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Validate Admin Token
function isAuthorizedAdmin(req) {
  const authHeader = req.headers['authorization'] || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.headers['x-admin-token']) {
    token = String(req.headers['x-admin-token']).trim();
  }

  if (!token) return false;
  const session = adminSessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function getEffectiveRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI && !process.env.GOOGLE_REDIRECT_URI.includes('localhost')) {
    return process.env.GOOGLE_REDIRECT_URI;
  }
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const host = req.headers.host || 'localhost:4000';
  return `${proto}://${host}/auth/google/callback`;
}

// -------------------------------------------------------------
// HTTP SERVER WITH SECURITY HEADERS & DEFENSES
// -------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const ip = getClientIp(req);
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const effectiveRedirectUri = getEffectiveRedirectUri(req);

  // Apply strict HTTP Security Headers to prevent clickjacking, MIME sniffing, XSS
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:;");

  // Global request rate limiting (120 req / minute per IP)
  if (!checkRateLimit(ip, 'ipRequests', 120, 60 * 1000)) {
    res.writeHead(429, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Too many requests. Please slow down.' }));
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const cleanPath = pathname.replace(/\/+$/, '') || '/';

  console.log(`[HTTP ${req.method}] ${pathname}`);

  // -------------------------------------------------------------
  // GET ROUTES
  // -------------------------------------------------------------
  if (req.method === 'GET') {
    // 1. Web Portal UI
    if (cleanPath === '/' || cleanPath === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
    }

    if (cleanPath === '/coming-soon' || cleanPath === '/coming-soon.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(path.join(__dirname, 'coming-soon.html')).pipe(res);
    }

    // 2. Static Assets
    if (cleanPath === '/logo.png') {
      const p = path.join(__dirname, 'logo.png');
      if (fs.existsSync(p)) {
        res.writeHead(200, { 'Content-Type': 'image/png' });
        return fs.createReadStream(p).pipe(res);
      }
    }

    if (cleanPath === '/logo.svg') {
      const p = path.join(__dirname, 'logo.svg');
      if (fs.existsSync(p)) {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
        return fs.createReadStream(p).pipe(res);
      }
    }

    // 3. Google OAuth Redirect
    if (cleanPath === '/auth/google') {
      if (!GOOGLE_CLIENT_ID) {
        res.writeHead(302, { Location: '/?google_config=needed' });
        return res.end();
      }

      const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      googleAuthUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
      googleAuthUrl.searchParams.set('redirect_uri', effectiveRedirectUri);
      googleAuthUrl.searchParams.set('response_type', 'code');
      googleAuthUrl.searchParams.set('scope', 'openid profile email');
      googleAuthUrl.searchParams.set('access_type', 'offline');
      googleAuthUrl.searchParams.set('prompt', 'select_account');

      res.writeHead(302, { Location: googleAuthUrl.toString() });
      return res.end();
    }

    // 4. Google OAuth Callback (Matches all standard callback paths)
    if (
      cleanPath === '/auth/google/callback' || 
      cleanPath === '/api/auth/callback/google' || 
      cleanPath === '/auth/callback' || 
      cleanPath === '/callback'
    ) {
      const code = parsedUrl.searchParams.get('code');
      const error = parsedUrl.searchParams.get('error');

      if (error || !code) {
        console.error('[Google OAuth] Error or missing code:', error);
        res.writeHead(302, { Location: `/?error=${encodeURIComponent(error || 'Access denied by Google')}` });
        return res.end();
      }

      try {
        console.log(`[Google OAuth] Exchanging code using redirect URI: ${effectiveRedirectUri}`);
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            redirect_uri: effectiveRedirectUri,
            grant_type: 'authorization_code'
          })
        });

        const tokenData = await tokenRes.json();
        if (!tokenRes.ok || !tokenData.access_token) {
          console.error('[Google OAuth Token Error]', tokenData);
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(`
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>OAuth Error</title></head>
            <body style="background:#0B1E36; color:#FFF; font-family:sans-serif; text-align:center; padding:50px;">
              <h2>Google Authentication Notice</h2>
              <p style="color:#F87171;">${tokenData.error_description || tokenData.error || 'Token exchange failed'}</p>
              <p style="color:#94A3B8; font-size:12px;">Redirect URI configured: <code>${effectiveRedirectUri}</code></p>
              <a href="/" style="color:#38BDF8; display:inline-block; margin-top:20px;">&larr; Return to BriefBay Home</a>
            </body>
            </html>
          `);
        }

        console.log('[Google OAuth] Fetching user profile info...');
        const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const googleUser = await userRes.json();

        console.log(`[Google OAuth Success] Authenticated: ${googleUser.email} (${googleUser.name})`);
        const returnUrl = new URL('/', `${proto}://${req.headers.host || 'localhost'}`);
        returnUrl.searchParams.set('google_auth', 'success');
        returnUrl.searchParams.set('email', googleUser.email || '');
        returnUrl.searchParams.set('name', googleUser.name || '');
        returnUrl.searchParams.set('picture', googleUser.picture || '');

        res.writeHead(302, { Location: returnUrl.pathname + returnUrl.search });
        return res.end();
      } catch (err) {
        console.error('OAuth callback error:', err);
        res.writeHead(302, { Location: `/?error=${encodeURIComponent(err.message)}` });
        return res.end();
      }
    }

    // 5. Public Stats Only (Aggregates Only - No Private User Data)
    if (pathname === '/api/stats') {
      const users = loadUsers();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: true, stats: getStats(users) }));
    }

    // 6. PROTECTED: GET /api/admin/users
    if (pathname === '/api/admin/users') {
      if (!isAuthorizedAdmin(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: false, error: 'Unauthorized: Admin authentication required.' }));
      }

      const users = loadUsers();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: true, users, stats: getStats(users) }));
    }
  }

  // -------------------------------------------------------------
  // POST ROUTES (WITH PAYLOAD SIZE RESTRICTION TO PREVENT DOS)
  // -------------------------------------------------------------
  if (req.method === 'POST') {
    let body = '';
    let size = 0;
    const MAX_SIZE = 50 * 1024; // 50KB limit

    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large.' }));
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
      let data = {};
      try {
        if (body) data = JSON.parse(body);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: false, error: 'Invalid JSON payload' }));
      }

      // ---------------------------------------------------------
      // 1. ADMIN LOGIN (PASSWORD PROTECTED & BRUTE-FORCE DEFENDED)
      // ---------------------------------------------------------
      if (pathname === '/api/admin/login') {
        const { username, password } = data;

        // Check if locked due to failed attempts
        if (!checkRateLimit(ip, 'loginAttempts', 5, 15 * 60 * 1000)) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Too many failed login attempts. Temporarily locked for 15 minutes.' }));
        }

        const validUser = safeCompare(username || '', ADMIN_USERNAME);
        const validPass = safeCompare(password || '', ADMIN_PASSWORD);

        if (!validUser || !validPass) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Invalid admin username or password.' }));
        }

        // Issue cryptographically secure session token
        const token = crypto.randomBytes(32).toString('hex');
        const session = {
          createdAt: Date.now(),
          expiresAt: Date.now() + (6 * 60 * 60 * 1000) // 6 hour valid session
        };
        adminSessions.set(token, session);

        // Reset rate limiter on successful auth
        rateLimits.loginAttempts.delete(ip);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          token,
          expiresIn: 6 * 3600
        }));
      }

      // ---------------------------------------------------------
      // 2. ADMIN LOGOUT
      // ---------------------------------------------------------
      if (pathname === '/api/admin/logout') {
        const token = req.headers['x-admin-token'] || '';
        if (token) adminSessions.delete(token);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: true }));
      }

      // ---------------------------------------------------------
      // 3. REGISTER USER (PUBLIC, RATE LIMITED & INPUT SANITIZED)
      // ---------------------------------------------------------
      if (pathname === '/api/register') {
        // Rate limit: Max 5 registrations per IP per 10 minutes
        if (!checkRateLimit(ip, 'registrations', 5, 10 * 60 * 1000)) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Registration limit reached from this IP. Please wait a few minutes.' }));
        }

        const { googleUser, username, password, role, email } = data;

        // Strict input validation
        if (!username || !email || !role) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Username, email, and role are required.' }));
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(normalizedEmail) || normalizedEmail.length > 254) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Invalid email address format.' }));
        }

        const cleanUsername = String(username).trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
        if (cleanUsername.length < 3 || cleanUsername.length > 24) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Username must be between 3 and 24 characters (letters, numbers, underscore only).' }));
        }

        const normalizedRole = role.toUpperCase() === 'FREELANCER' ? 'FREELANCER' : 'CLIENT';

        const users = loadUsers();

        // Check for duplicates
        if (users.find(u => u.username.toLowerCase() === cleanUsername)) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: `Username @${cleanUsername} is already registered.` }));
        }

        if (users.find(u => u.email.toLowerCase() === normalizedEmail)) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: `Email ${normalizedEmail} has already claimed early access.` }));
        }

        // Calculate early access spot & VIP status
        const sameRoleVipUsers = users.filter(u => u.role === normalizedRole && u.isFirst15);
        const isFirst15 = sameRoleVipUsers.length < 15;
        const rank = sameRoleVipUsers.length + 1;

        let perk = '';
        if (normalizedRole === 'CLIENT') {
          perk = isFirst15 ? '25% OFF on first purchase' : 'Standard Early Access';
        } else {
          perk = isFirst15 ? 'Featured & Promoted Gig / Work' : 'Standard Early Access';
        }

        const newUser = {
          id: `BB-${isFirst15 ? 'VIP' : 'MEM'}-${String(users.length + 1).padStart(3, '0')}`,
          username: cleanUsername,
          email: normalizedEmail,
          role: normalizedRole,
          isFirst15,
          rank: isFirst15 ? rank : users.filter(u => u.role === normalizedRole).length + 1,
          perk,
          avatar: googleUser?.picture || `https://api.dicebear.com/7.x/identicon/svg?seed=${cleanUsername}`,
          createdAt: new Date().toISOString(),
          syncedToMarketplace: false
        };

        // Sync directly into BriefBay SQLite database
        const syncResult = syncUserToBriefBay(newUser);
        newUser.syncedToMarketplace = syncResult.success;

        users.push(newUser);
        saveUsers(users);

        res.writeHead(201, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          user: newUser,
          stats: getStats(users)
        }));
      }

      // ---------------------------------------------------------
      // 4. PROTECTED: REMOVE USER FROM TOP 15 LIST
      // ---------------------------------------------------------
      if (pathname === '/api/admin/remove-vip') {
        if (!isAuthorizedAdmin(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
        }

        const { email } = data;
        if (!email) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User email is required.' }));
        }

        const users = loadUsers();
        const target = users.find(u => u.email.toLowerCase() === email.toLowerCase());

        if (!target) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User not found in registry.' }));
        }

        // Demote from Top 15
        target.isFirst15 = false;
        target.perk = 'Standard Early Access';
        target.id = target.id.replace('VIP', 'MEM');

        // Update BriefBay database
        updateUserVipStatus(target.email, false, 'Standard Early Access');

        // Recompute VIP ranks for that role
        const remainingVips = users.filter(u => u.role === target.role && u.isFirst15);
        remainingVips.forEach((u, idx) => {
          u.rank = idx + 1;
        });

        saveUsers(users);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          message: `User @${target.username} has been removed from the Top 15 list.`,
          user: target,
          stats: getStats(users),
          users
        }));
      }

      // ---------------------------------------------------------
      // 5. PROTECTED: TOGGLE VIP STATUS
      // ---------------------------------------------------------
      if (pathname === '/api/admin/toggle-vip') {
        if (!isAuthorizedAdmin(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
        }

        const { email } = data;
        if (!email) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User email is required.' }));
        }

        const users = loadUsers();
        const target = users.find(u => u.email.toLowerCase() === email.toLowerCase().trim());

        if (!target) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User not found in registry.' }));
        }

        target.isFirst15 = !target.isFirst15;
        if (target.isFirst15) {
          const sameVips = users.filter(u => u.role === target.role && u.isFirst15);
          target.rank = sameVips.length;
          target.perk = target.role === 'CLIENT' ? '25% OFF on first purchase' : 'Featured & Promoted Gig / Work';
          target.id = target.id.replace('MEM', 'VIP');
        } else {
          target.perk = 'Standard Early Access';
          target.id = target.id.replace('VIP', 'MEM');
        }

        updateUserVipStatus(target.email, target.isFirst15, target.perk);

        // Recompute ranks
        const remainingVips = users.filter(u => u.role === target.role && u.isFirst15);
        remainingVips.forEach((u, idx) => { u.rank = idx + 1; });

        saveUsers(users);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          message: `VIP status for @${target.username} set to ${target.isFirst15 ? 'VIP' : 'Standard'}.`,
          user: target,
          stats: getStats(users),
          users
        }));
      }

      // ---------------------------------------------------------
      // 6. PROTECTED: DELETE USER COMPLETELY FROM REGISTRY & DB
      // ---------------------------------------------------------
      if (pathname === '/api/admin/delete-user') {
        if (!isAuthorizedAdmin(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
        }

        const { email } = data;
        if (!email) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User email is required.' }));
        }

        let users = loadUsers();
        const normalized = email.toLowerCase().trim();
        const target = users.find(u => u.email.toLowerCase() === normalized);

        if (!target) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'User not found in registry.' }));
        }

        // Delete from BriefBay SQLite database
        deleteUserFromBriefBay(normalized);

        // Remove from memory
        users = users.filter(u => u.email.toLowerCase() !== normalized);

        // Recompute ranks for remaining VIPs
        const remainingVips = users.filter(u => u.role === target.role && u.isFirst15);
        remainingVips.forEach((u, idx) => { u.rank = idx + 1; });

        saveUsers(users);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          message: `User @${target.username} (${target.email}) permanently deleted.`,
          stats: getStats(users),
          users
        }));
      }

      // ---------------------------------------------------------
      // 5. PROTECTED: ONE-CLICK SYNC ALL TO BRIEFBAY DB
      // ---------------------------------------------------------
      if (pathname === '/api/admin/sync') {
        if (!isAuthorizedAdmin(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
        }

        const users = loadUsers();
        const report = syncAllUsers(users);
        users.forEach(u => { u.syncedToMarketplace = true; });
        saveUsers(users);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          message: `Synchronized ${report.synced} users to BriefBay marketplace database.`,
          report
        }));
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found' }));
    });
    return;
  }

  console.warn(`[404 Not Found] ${req.method} ${pathname}`);
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not Found</title></head><body style="background:#0B1E36;color:#FFF;font-family:sans-serif;text-align:center;padding:50px;"><h2>Page Not Found</h2><p style="color:#94A3B8;">The URL <code>${pathname}</code> was not found.</p><a href="/" style="color:#38BDF8;">&larr; Return to BriefBay Home</a></body></html>`);
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️ BriefBay Pre-Release Portal is SECURE & LIVE!`);
  console.log(`🌐 Public Portal:           http://localhost:${PORT}`);
  console.log(`🔒 Hidden Admin Portal:     http://localhost:${PORT}#admin`);
  console.log(`🔑 Admin Username:          ${ADMIN_USERNAME}`);
  console.log(`🔑 Admin Password:          ${ADMIN_PASSWORD}`);
  console.log(`🔗 Connected DB:            c:/Users/Burhan Khan/Desktop/BreifBay/prisma/dev.db`);
  console.log(`====================================================`);
});
