// ═══════════════════════════════════════════════════════════════════════════
// ⚡ SPARK TERMINAL — gateway v2 (beta launch)
//
// AUTH: native Google sign-in — OAuth implemented directly in this worker,
//       no third-party auth service. Passwordless: we never store passwords.
//       Google hands us a verified identity; we issue our own signed
//       HttpOnly cookie. Beta gate: new accounts redeem a one-time invite.
// KEYS: Finnhub/OpenAI keys exist ONLY as Cloudflare secrets. The browser
//       talks to /api/* — no key ever appears in HTML, JS, or network traffic.
// DATA: D1 database. Private notes are scoped WHERE user=<session uid> in
//       every query. Social content (profiles/theses/comments) is member-visible.
// ABUSE: per-user+IP rate limits, per-user daily AI cap (KV), banned table,
//       strict security headers (CSP etc.) on everything we serve.
//
// Secrets: FINNHUB_KEY, OPENAI_KEY, SESSION_SECRET, GOOGLE_CLIENT_SECRET
// Vars:    GOOGLE_CLIENT_ID, AI_MODEL, AI_DAILY_LIMIT, BETA_GATE
// Bindings: ASSETS (static), DB (D1), KV (AI counters)
// ═══════════════════════════════════════════════════════════════════════════

const COOKIE = 'spark_sess';
const SESSION_DAYS = 30;

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });

// ── sessions: HMAC-signed HttpOnly cookie holding the account uid ──────────
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
}
async function makeSession(env, uid) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  return `${uid}.${exp}.${await hmac(env.SESSION_SECRET, uid + '.' + exp)}`;
}
async function checkSession(env, request) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp(COOKIE + '=([^;]+)'));
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 3) return null;
  const [uid, exp, sig] = parts;
  if (!uid || Date.now() > +exp) return null;
  return sig === await hmac(env.SESSION_SECRET, uid + '.' + exp) ? uid : null;
}
const sessionCookie = (v, maxAge) =>
  `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

// generic signed values (OAuth state param, pending-invite cookie)
const b64u = s => btoa(unescape(encodeURIComponent(s))).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
const unb64u = s => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/'))));
async function signVal(env, obj, ttlMs) {
  const body = b64u(JSON.stringify({ ...obj, exp: Date.now() + ttlMs }));
  return body + '.' + await hmac(env.SESSION_SECRET, body);
}
async function readVal(env, v) {
  if (!v) return null;
  const [body, sig] = String(v).split('.');
  if (!body || !sig || sig !== await hmac(env.SESSION_SECRET, body)) return null;
  try {
    const o = JSON.parse(unb64u(body));
    return Date.now() > o.exp ? null : o;
  } catch { return null; }
}
const cookieVal = (request, name) =>
  ((request.headers.get('Cookie') || '').match(new RegExp(name + '=([^;]+)')) || [])[1] || null;

// ── rate limiting: in-memory per-isolate minute buckets (free, no KV writes) ─
const rl = new Map();
function rateLimit(key, limit) {
  const bucket = Math.floor(Date.now() / 60000);
  const k = key + ':' + bucket;
  const n = (rl.get(k) || 0) + 1;
  rl.set(k, n);
  if (rl.size > 8000) for (const kk of rl.keys()) { if (!kk.endsWith(':' + bucket)) rl.delete(kk); }
  return n <= limit;
}
const ipOf = r => r.headers.get('CF-Connecting-IP') || 'unknown';

// ── security headers on everything we serve ────────────────────────────────
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "frame-src https://www.tradingview.com https://*.tradingview.com",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');
function harden(res) {
  const r = new Response(res.body, res);
  r.headers.set('Content-Security-Policy', CSP);
  r.headers.set('X-Content-Type-Options', 'nosniff');
  r.headers.set('Referrer-Policy', 'no-referrer');
  r.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return r;
}

// ── cached upstream proxy (same-origin for the browser → no CORS anywhere) ──
async function cachedProxy(target, ttl, ctx, forceType) {
  const cache = caches.default;
  const key = new Request(target);
  const hit = await cache.match(key);
  if (hit) return hit;
  const up = await fetch(target, { headers: { 'User-Agent': 'SparkTerminal/1.0', 'Accept': 'application/json,text/csv,*/*' } });
  const res = new Response(up.body, {
    status: up.status,
    headers: {
      'Content-Type': forceType || up.headers.get('Content-Type') || 'application/json',
      'Cache-Control': `public, max-age=${ttl}`,
    },
  });
  if (up.ok) ctx.waitUntil(cache.put(key, res.clone()));
  return res;
}

// ── AI proxy: streaming passthrough + per-member daily cap ──────────────────
async function aiProxy(request, env, user) {
  if (!env.OPENAI_KEY)
    return json({ error: { message: 'AI features aren\'t enabled on this server yet — everything else works. (Owner: add an OPENAI_KEY, or a free OpenRouter key + AI_BASE_URL, in the worker settings.)' } }, 501);
  const limit = parseInt(env.AI_DAILY_LIMIT || '25', 10);
  const day = new Date().toISOString().slice(0, 10);
  const k = `ai:${user}:${day}`;
  let used = 0;
  if (env.KV) {
    used = parseInt((await env.KV.get(k)) || '0', 10);
    if (used >= limit)
      return json({ error: { message: `Daily AI limit reached (${limit}/day per member). Resets midnight UTC.` } }, 429);
  }
  const { system, prompt, max_tokens } = await request.json().catch(() => ({}));
  if (!prompt) return json({ error: { message: 'missing prompt' } }, 400);
  // AI_BASE_URL lets you swap providers: default OpenAI; set
  // https://openrouter.ai/api/v1 + an OpenRouter key + a ":free" model for $0 AI
  const up = await fetch((env.AI_BASE_URL || 'https://api.openai.com/v1') + '/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.OPENAI_KEY },
    body: JSON.stringify({
      model: env.AI_MODEL || 'gpt-4o-mini',
      stream: true,
      max_tokens: Math.min(max_tokens || 1800, 2500),
      messages: [
        { role: 'system', content: String(system || '').slice(0, 4000) },
        { role: 'user', content: String(prompt).slice(0, 16000) },
      ],
    }),
  });
  if (env.KV && up.ok) await env.KV.put(k, String(used + 1), { expirationTtl: 172800 });
  return new Response(up.body, {
    status: up.status,
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' },
  });
}

// ── D1 social API ───────────────────────────────────────────────────────────
// stocks (MU), crypto (BTC), futures (/ES, ES=F) and DEX pairs (DX:solana:<addr>)
const SYM_RE = /^(DX:[a-z0-9]+:[A-Za-z0-9]{20,64}|[A-Z0-9./=\-]{1,10})$/;

// every new account gets a starter profile (name/handle from their email),
// so members are searchable immediately — before they ever edit anything
async function seedProfile(env, uid, email) {
  const local = String(email || '').split('@')[0] || 'member';
  const handle = local.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20) || 'member';
  const name = (local.charAt(0).toUpperCase() + local.slice(1)).slice(0, 20);
  await env.DB.prepare(
    'INSERT OR IGNORE INTO profiles (user,name,handle,bio,emoji,img,joined) VALUES (?1,?2,?3,\'\',\'\',\'\',?4)'
  ).bind(uid, name, handle, Date.now()).run();
}
async function isBanned(env, uid) {
  return !!(await env.DB.prepare('SELECT uid FROM banned WHERE uid=?1').bind(uid).first());
}

async function social(request, env, user, url) {
  const path = url.pathname;
  const writing = request.method === 'POST';
  if (writing) {
    if (!rateLimit('w:' + user, 30)) return json({ error: 'slow down' }, 429);
    if (await isBanned(env, user)) return json({ error: 'account suspended' }, 403);
  }

  if (path === '/api/social/profile') {
    if (writing) {
      const b = await request.json().catch(() => ({}));
      await env.DB.prepare(
        `INSERT INTO profiles (user,name,handle,bio,emoji,img,joined)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(user) DO UPDATE SET name=?2,handle=?3,bio=?4,emoji=?5,img=?6`
      ).bind(
        user,
        String(b.name || '').slice(0, 20),
        String(b.handle || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20),
        String(b.bio || '').slice(0, 200),
        String(b.emoji || '⚡').slice(0, 8),
        typeof b.img === 'string' && b.img.startsWith('data:image/') ? b.img.slice(0, 40000) : '',
        Date.now()
      ).run();
      return json({ ok: true });
    }
    const row = await env.DB.prepare('SELECT * FROM profiles WHERE user=?1').bind(user).first();
    return json(row || null);
  }

  // per-account settings (watchlists etc) → follows the login across devices
  if (path === '/api/social/prefs') {
    if (writing) {
      const b = await request.text();
      await env.DB.prepare('INSERT INTO prefs (user,data,updated) VALUES (?1,?2,?3) ON CONFLICT(user) DO UPDATE SET data=?2,updated=?3')
        .bind(user, String(b || '').slice(0, 40000), Date.now()).run();
      return json({ ok: true });
    }
    const row = await env.DB.prepare('SELECT data FROM prefs WHERE user=?1').bind(user).first();
    try { return json(row && row.data ? JSON.parse(row.data) : null); } catch { return json(null); }
  }

  if (path === '/api/social/members') {
    const { results } = await env.DB.prepare(
      `SELECT p.user,p.name,p.handle,p.bio,p.emoji,p.img,p.joined,
              (SELECT COUNT(*) FROM theses t WHERE t.user=p.user) AS theses,
              (SELECT COUNT(*) FROM follows f WHERE f.followee=p.user) AS followers
       FROM profiles p ORDER BY followers DESC, theses DESC LIMIT 200`).all();
    return json(results || []);
  }

  // ── FOLLOWS ── the social graph
  if (path === '/api/social/follow' && writing) {
    const b = await request.json().catch(() => ({}));
    const target = String(b.user || '');
    if (!target || target === user) return json({ error: 'bad target' }, 400);
    if (b.action === 'unfollow')
      await env.DB.prepare('DELETE FROM follows WHERE follower=?1 AND followee=?2').bind(user, target).run();
    else
      await env.DB.prepare('INSERT OR IGNORE INTO follows (follower,followee,created) VALUES (?1,?2,?3)')
        .bind(user, target, Date.now()).run();
    return json({ ok: true });
  }
  if (path === '/api/social/followstats') {
    const u = url.searchParams.get('user') || user;
    const followers = await env.DB.prepare('SELECT COUNT(*) AS c FROM follows WHERE followee=?1').bind(u).first();
    const following = await env.DB.prepare('SELECT COUNT(*) AS c FROM follows WHERE follower=?1').bind(u).first();
    const you = u === user ? null
      : await env.DB.prepare('SELECT 1 AS y FROM follows WHERE follower=?1 AND followee=?2').bind(user, u).first();
    return json({ followers: followers?.c || 0, following: following?.c || 0, youFollow: !!you });
  }

  if (path === '/api/social/thesis' && writing) {
    const b = await request.json().catch(() => ({}));
    const sym = String(b.sym || '').toUpperCase();
    if (!SYM_RE.test(sym)) return json({ error: 'bad symbol' }, 400);
    const text = String(b.text || '').trim().slice(0, 600);
    if (!text) {
      await env.DB.prepare('DELETE FROM theses WHERE user=?1 AND sym=?2').bind(user, sym).run();
      return json({ ok: true, deleted: true });
    }
    const stance = ['bull', 'bear', 'neutral'].includes(b.stance) ? b.stance : 'neutral';
    await env.DB.prepare(
      `INSERT INTO theses (user,sym,stance,text,px,updated) VALUES (?1,?2,?3,?4,?5,?6)
       ON CONFLICT(user,sym) DO UPDATE SET stance=?3,text=?4,px=?5,updated=?6`
    ).bind(user, sym, stance, text, typeof b.px === 'number' ? b.px : null, Date.now()).run();
    return json({ ok: true });
  }

  if (path === '/api/social/theses') {
    const sym = (url.searchParams.get('sym') || '').toUpperCase();
    const forUser = url.searchParams.get('user');
    let q;
    if (sym && SYM_RE.test(sym))
      q = env.DB.prepare(
        `SELECT t.*,p.name,p.handle,p.emoji,p.img FROM theses t
         LEFT JOIN profiles p ON p.user=t.user
         WHERE t.sym=?1 ORDER BY t.updated DESC LIMIT 100`).bind(sym);
    else
      q = env.DB.prepare(
        `SELECT t.*,p.name,p.handle,p.emoji,p.img FROM theses t
         LEFT JOIN profiles p ON p.user=t.user
         WHERE t.user=?1 ORDER BY t.updated DESC LIMIT 200`).bind(forUser || user);
    const { results } = await q.all();
    return json(results || []);
  }

  // PRIVATE NOTES — every statement scoped to the session uid; nobody else's
  // notes ever leave the server, regardless of what a client requests
  if (path === '/api/social/notes' && writing) {
    const b = await request.json().catch(() => ({}));
    const sym = String(b.sym || '').toUpperCase();
    if (!SYM_RE.test(sym)) return json({ error: 'bad symbol' }, 400);
    const text = String(b.text || '').trim().slice(0, 2000);
    if (!text) return json({ error: 'empty' }, 400);
    const r = await env.DB.prepare('INSERT INTO notes (user,sym,text,px,created) VALUES (?1,?2,?3,?4,?5)')
      .bind(user, sym, text, typeof b.px === 'number' ? b.px : null, Date.now()).run();
    return json({ ok: true, id: r.meta?.last_row_id });
  }
  if (path === '/api/social/notes') {
    const sym = (url.searchParams.get('sym') || '').toUpperCase();
    if (!SYM_RE.test(sym)) return json({ error: 'bad symbol' }, 400);
    const { results } = await env.DB.prepare(
      'SELECT id,sym,text,px,created FROM notes WHERE user=?1 AND sym=?2 ORDER BY created DESC LIMIT 200')
      .bind(user, sym).all();
    return json(results || []);
  }
  if (path === '/api/social/notes/delete' && writing) {
    const b = await request.json().catch(() => ({}));
    await env.DB.prepare('DELETE FROM notes WHERE id=?1 AND user=?2').bind(+b.id || 0, user).run();
    return json({ ok: true });
  }

  if (path === '/api/social/comment' && writing) {
    const b = await request.json().catch(() => ({}));
    const sym = String(b.sym || '').toUpperCase();
    if (!SYM_RE.test(sym)) return json({ error: 'bad symbol' }, 400);
    const text = String(b.text || '').trim().slice(0, 400);
    if (!text) return json({ error: 'empty' }, 400);
    await env.DB.prepare('INSERT INTO comments (user,sym,text,created) VALUES (?1,?2,?3,?4)')
      .bind(user, sym, text, Date.now()).run();
    return json({ ok: true });
  }
  if (path === '/api/social/comments') {
    const sym = (url.searchParams.get('sym') || '').toUpperCase();
    if (!SYM_RE.test(sym)) return json({ error: 'bad symbol' }, 400);
    const { results } = await env.DB.prepare(
      `SELECT c.id,c.user,c.sym,c.text,c.created,p.name,p.handle,p.emoji,p.img
       FROM comments c LEFT JOIN profiles p ON p.user=c.user
       WHERE c.sym=?1 ORDER BY c.created DESC LIMIT 100`).bind(sym).all();
    return json(results || []);
  }

  return json({ error: 'not found' }, 404);
}

// ── sign-in page: pure server-rendered, no third-party scripts ──────────────
// mode 'login' → Google button · mode 'invite' → redeem form (signed-in, gated)
const loginHtml = (mode = 'login', email = '', err = '') => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Due Diligence Terminal — Sign in</title><style>
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#060810;color:#dde3f0;font-family:'SF Mono','Fira Code',Consolas,monospace}
.box{width:340px;padding:32px;background:#0d1018;border:1px solid #252f44;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.55)}
h1{font-size:16px;letter-spacing:1.5px;color:#00d4ff;text-shadow:0 0 20px rgba(0,212,255,.35);margin:0 0 6px}
p{font-size:11px;color:#7a88a8;line-height:1.6;margin:0 0 16px}
input{width:100%;box-sizing:border-box;background:#11151f;border:1px solid #252f44;border-radius:5px;padding:11px 12px;color:#dde3f0;font-size:13px;font-family:inherit;outline:none;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}
input:focus{border-color:#00d4ff;box-shadow:0 0 0 3px rgba(0,212,255,.15)}
a.g,button{width:100%;box-sizing:border-box;border:none;border-radius:5px;padding:12px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;letter-spacing:.5px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:8px}
a.g{background:#fff;color:#1a1a1a}
button{background:#00d4ff;color:#000}
a.g:hover,button:hover{opacity:.9}
.msg{font-size:11px;margin-top:12px;min-height:16px;line-height:1.5;color:#ff3d57}
.ok{color:#00e676}
.foot{font-size:9px;color:#4e5a76;margin-top:16px;line-height:1.6}
</style></head><body><div class="box">
<h1>DUE DILIGENCE TERMINAL</h1>
${mode === 'invite' ? `
<p class="ok">✅ Signed in${email ? ' as ' + email : ''}.<br>This beta is invite-only — enter your code to activate.</p>
<form method="POST" action="/auth/redeem">
  <input name="invite" placeholder="INVITE CODE" maxlength="40" autofocus autocomplete="off">
  <button type="submit">REDEEM &amp; ENTER</button>
</form>
<div class="msg">${err}</div>
` : `
<p>Market data, social theses, AI ideas — one terminal.</p>
<a class="g" href="/auth/google">
  <svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.5l6.7-6.7C35.6 2.4 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.8 6.1C12.3 13.4 17.7 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8c4.4-4.1 7.1-10.1 7.1-17.5z"/><path fill="#FBBC05" d="M10.4 28.7a14.5 14.5 0 0 1 0-9.4l-7.8-6.1a24 24 0 0 0 0 21.6l7.8-6.1z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.5-5.8c-2.1 1.4-4.7 2.2-7.7 2.2-6.3 0-11.7-3.9-13.6-9.5l-7.8 6.1C6.5 42.6 14.6 48 24 48z"/></svg>
  CONTINUE WITH GOOGLE
</a>
<div class="msg">${err}</div>
`}
<div class="foot">Private beta — new accounts need an invite code.<br>No passwords, ever: Google verifies you, we never see credentials.<br>Not investment advice. Market data for personal use.</div>
</div></body></html>`;

// ── router ──────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (e) {
      // beta-friendly: name the failure instead of a blank Cloudflare 1101
      return new Response(
        'Due Diligence Terminal hit an error: ' + (e && e.message ? e.message : String(e)) +
        '\n\nIf this mentions a missing key/binding, add it under the worker\'s Settings and reload.',
        { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }
  },
};

async function handle(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // self-diagnosis: if setup is incomplete, say exactly what's missing
    const missing = ['SESSION_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'FINNHUB_KEY']
      .filter(k => !env[k]); // OPENAI_KEY is optional — without it, only AI features are off
    if (!env.DB) missing.push('DB (D1 database binding)');
    if (!env.KV) missing.push('KV (KV namespace binding)');
    if (missing.length) {
      if (path.startsWith('/api/')) return json({ error: 'setup incomplete: ' + missing.join(', ') }, 500);
      return new Response(
        `<!DOCTYPE html><html><body style="background:#060810;color:#dde3f0;font-family:monospace;padding:40px;line-height:1.8">
        <h2 style="color:#ffb300">Due Diligence Terminal — setup incomplete</h2>
        <p>The worker is deployed, but this configuration is missing:</p>
        <p style="color:#ff3d57;font-weight:bold">${missing.join('<br>')}</p>
        <p>Fix: Cloudflare dashboard → your worker → <b>Settings</b> →<br>
        “Variables and Secrets” for keys (names must match EXACTLY, all caps) ·<br>
        “Bindings” for DB / KV (variable names exactly <b>DB</b> and <b>KV</b>).</p>
        <p>Then reload this page — this message disappears when everything is set.</p>
        </body></html>`,
        { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    const origin = url.origin;
    const htmlRes = (body, extra = {}) =>
      harden(new Response(body, { headers: { 'Content-Type': 'text/html', ...extra } }));
    const enter = async uid => new Response(null, {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': sessionCookie(await makeSession(env, uid), SESSION_DAYS * 86400),
      },
    });

    // step 1: send the user to Google with a signed anti-CSRF state
    if (path === '/auth/google') {
      if (!rateLimit('auth:' + ipOf(request), 20)) return new Response('slow down', { status: 429 });
      const state = await signVal(env, { n: crypto.randomUUID() }, 10 * 60000);
      const p = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        redirect_uri: origin + '/auth/callback',
        response_type: 'code',
        scope: 'openid email',
        state,
        prompt: 'select_account',
      });
      return Response.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + p, 302);
    }

    // step 2: Google redirects back — exchange the code, verify identity
    if (path === '/auth/callback') {
      if (!await readVal(env, url.searchParams.get('state')))
        return htmlRes(loginHtml('login', '', 'Sign-in expired — try again'));
      const code = url.searchParams.get('code');
      if (!code) return htmlRes(loginHtml('login', '', 'Google sign-in was cancelled'));
      const tr = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: origin + '/auth/callback',
          grant_type: 'authorization_code',
        }),
      });
      if (!tr.ok) return htmlRes(loginHtml('login', '', 'Google rejected the sign-in — try again'));
      const tok = await tr.json();
      // id_token came directly from Google over TLS — decode and sanity-check
      let claims = {};
      try { claims = JSON.parse(unb64u((tok.id_token || '').split('.')[1] || '')); } catch {}
      if (claims.aud !== env.GOOGLE_CLIENT_ID || !String(claims.iss || '').includes('accounts.google.com') || !claims.sub)
        return htmlRes(loginHtml('login', '', 'Could not verify the sign-in'));
      const uid = 'g_' + claims.sub;
      const email = claims.email || '';
      if (await isBanned(env, uid)) return htmlRes(loginHtml('login', '', 'This account is suspended'));

      const acct = await env.DB.prepare('SELECT uid FROM accounts WHERE uid=?1').bind(uid).first();
      if (acct) return enter(uid);
      if ((env.BETA_GATE ?? '1') !== '1') {
        await env.DB.prepare('INSERT INTO accounts (uid,email,created,invite) VALUES (?1,?2,?3,NULL)').bind(uid, email, Date.now()).run();
        await seedProfile(env, uid, email);
        return enter(uid);
      }
      // gated: park the verified identity in a short-lived signed cookie,
      // show the invite form
      const pend = await signVal(env, { uid, email }, 15 * 60000);
      return htmlRes(loginHtml('invite', email), { 'Set-Cookie': `spark_pend=${pend}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900` });
    }

    // step 3 (gated beta only): redeem the one-time invite code
    if (path === '/auth/redeem' && request.method === 'POST') {
      if (!rateLimit('redeem:' + ipOf(request), 10)) return new Response('slow down', { status: 429 });
      const pend = await readVal(env, cookieVal(request, 'spark_pend'));
      if (!pend?.uid) return htmlRes(loginHtml('login', '', 'Session expired — sign in again'));
      const form = await request.formData().catch(() => null);
      const code = String(form?.get('invite') || '').trim().toUpperCase();
      const row = code && await env.DB.prepare('SELECT code FROM invites WHERE code=?1 AND used_by IS NULL').bind(code).first();
      if (!row) return htmlRes(loginHtml('invite', pend.email, 'Invalid or already-used invite code'));
      await env.DB.prepare('UPDATE invites SET used_by=?1, used_at=?2 WHERE code=?3').bind(pend.uid, Date.now(), code).run();
      await env.DB.prepare('INSERT OR IGNORE INTO accounts (uid,email,created,invite) VALUES (?1,?2,?3,?4)').bind(pend.uid, pend.email, Date.now(), code).run();
      await seedProfile(env, pend.uid, pend.email);
      const res = await enter(pend.uid);
      res.headers.append('Set-Cookie', 'spark_pend=; Path=/; Max-Age=0');
      return res;
    }

    if (path === '/logout')
      return new Response(null, { status: 302, headers: { 'Location': '/', 'Set-Cookie': sessionCookie('', 0) } });

    const user = await checkSession(env, request);
    if (!user) {
      if (path.startsWith('/api/')) return json({ error: 'unauthorized' }, 401);
      return htmlRes(loginHtml());
    }

    // generous per-user API ceiling — protects the shared keys from runaway loops
    if (path.startsWith('/api/') && !rateLimit('api:' + user, 300))
      return json({ error: 'rate limited' }, 429);

    if (path.startsWith('/api/finnhub/')) {
      const t = new URL('https://finnhub.io/api/v1/' + path.slice('/api/finnhub/'.length) + url.search);
      t.searchParams.set('token', env.FINNHUB_KEY);
      return cachedProxy(t.toString(), 25, ctx);
    }
    if (path.startsWith('/api/cg/'))
      return cachedProxy('https://api.coingecko.com/api/v3/' + path.slice(8) + url.search, 30, ctx);
    if (path.startsWith('/api/aw/'))
      return cachedProxy('https://apewisdom.io/api/v1.0/' + path.slice(8), 300, ctx);
    if (path.startsWith('/api/ds/')) // DexScreener: on-chain pairs, 300 req/min
      return cachedProxy('https://api.dexscreener.com/' + path.slice(8) + url.search, 45, ctx);
    if (path.startsWith('/api/st/'))
      return cachedProxy('https://api.stocktwits.com/api/2/' + path.slice(8), 60, ctx);
    if (path === '/api/fred')
      return cachedProxy('https://fred.stlouisfed.org/graph/fredgraph.csv?' + url.searchParams.toString(), 3600, ctx, 'text/csv');
    if (path.startsWith('/api/yf/')) // futures quotes need to stay fresh
      return cachedProxy('https://query1.finance.yahoo.com/' + path.slice(8) + url.search,
        url.search.includes('range=5d') ? 60 : 300, ctx);
    if (path === '/api/ai' && request.method === 'POST') {
      if (await isBanned(env, user)) return json({ error: { message: 'account suspended' } }, 403);
      return aiProxy(request, env, user);
    }
    if (path === '/api/me') {
      const acct = await env.DB.prepare('SELECT uid,email,created FROM accounts WHERE uid=?1').bind(user).first();
      return json({ ...(acct || { uid: user }), ai: !!env.OPENAI_KEY, av: !!env.AV_KEY });
    }
    // Alpha Vantage — confirmed earnings dates + clean adjusted EPS (optional,
    // needs AV_KEY). Cached 12h because earnings only change quarterly, which
    // keeps us well under the free 25-requests/day limit.
    if (path === '/api/av') {
      if (!env.AV_KEY) return json({ note: 'AV not configured' }, 501);
      const qs = url.search || '';
      // KV cache for a WEEK: earnings change only quarterly, so each symbol costs
      // one Alpha Vantage call per week — keeps every stock working under the
      // free 25/day limit instead of starving after ~25 lookups.
      const kvKey = 'av' + qs;
      if (env.KV) {
        const hit = await env.KV.get(kvKey);
        if (hit) return new Response(hit, { headers: { 'Content-Type': 'application/json', 'X-Cache': 'kv' } });
      }
      let body = '{}';
      try {
        const up = await fetch('https://www.alphavantage.co/query' + qs + '&apikey=' + env.AV_KEY);
        body = await up.text();
      } catch {}
      // only cache real data — never cache a rate-limit "Information" note
      if (env.KV && (body.includes('quarterlyEarnings') || body.includes('annualEarnings')))
        ctx.waitUntil(env.KV.put(kvKey, body, { expirationTtl: 604800 }));
      return new Response(body, { headers: { 'Content-Type': 'application/json' } });
    }
    // Polymarket prediction markets related to a query (company / ticker / topic).
    // We fetch Polymarket's big search payload server-side and trim it to a small
    // list the client can render; cached 5 min.
    if (path === '/api/poly') {
      const q = (url.searchParams.get('q') || '').slice(0, 60);
      if (!q) return json([]);
      const ck = 'poly:' + q.toLowerCase();
      if (env.KV) { const hit = await env.KV.get(ck); if (hit) return new Response(hit, { headers: { 'Content-Type': 'application/json', 'X-Cache': 'kv' } }); }
      let out = [];
      try {
        const r = await fetch('https://gamma-api.polymarket.com/public-search?q=' + encodeURIComponent(q) + '&limit_per_type=12&events_status=active',
          { headers: { 'User-Agent': 'DueDiligence/1.0' } });
        const d = await r.json();
        (d.events || []).forEach(ev => {
          (ev.markets || []).forEach(mk => {
            if (mk.closed || mk.active === false) return;
            let prices = [], outs = [];
            try { prices = JSON.parse(mk.outcomePrices || '[]'); } catch {}
            try { outs = JSON.parse(mk.outcomes || '[]'); } catch {}
            const vol = parseFloat(mk.volume || ev.volume || 0) || 0;
            out.push({
              q: mk.question || ev.title || '',
              yes: prices[0] != null ? parseFloat(prices[0]) : null,
              o0: outs[0] || 'Yes', o1: outs[1] || 'No',
              vol, end: mk.endDate || ev.endDate || null,
              url: 'https://polymarket.com/event/' + (ev.slug || ''),
            });
          });
        });
        // de-dupe by question, biggest volume first, top 10
        const seen = new Set();
        out = out.filter(m => m.q && !seen.has(m.q) && seen.add(m.q))
          .sort((a, b) => b.vol - a.vol).slice(0, 10);
      } catch {}
      const body = JSON.stringify(out);
      if (env.KV && out.length) ctx.waitUntil(env.KV.put(ck, body, { expirationTtl: 300 }));
      return new Response(body, { headers: { 'Content-Type': 'application/json' } });
    }
    // ── DEX MARKET (DexScreener, no key) ── screener search, trending, per-token pairs
    if (path === '/api/dex') {
      const type = (url.searchParams.get('type') || 'search').slice(0, 12);
      const q = (url.searchParams.get('q') || '').slice(0, 80);
      const addr = (url.searchParams.get('addr') || '').slice(0, 700);
      const ck = 'dex:' + type + ':' + (q || addr).toLowerCase();
      // trim a raw DexScreener pair to a compact row
      const trim = (p) => {
        const t = (p.txns && p.txns.h24) || {};
        return {
          chain: p.chainId, dex: p.dexId, url: p.url, pair: p.pairAddress,
          sym: (p.baseToken && p.baseToken.symbol) || '', name: (p.baseToken && p.baseToken.name) || '',
          addr: (p.baseToken && p.baseToken.address) || '', quote: (p.quoteToken && p.quoteToken.symbol) || '',
          price: p.priceUsd != null ? parseFloat(p.priceUsd) : null,
          chg: (p.priceChange && p.priceChange.h24 != null) ? p.priceChange.h24 : null,
          vol: (p.volume && p.volume.h24) || 0,
          liq: (p.liquidity && p.liquidity.usd) || 0,
          mc: p.marketCap || p.fdv || 0,
          buys: t.buys || 0, sells: t.sells || 0,
          age: p.pairCreatedAt || null,
          img: (p.info && p.info.imageUrl) || null,
          boost: (p.boosts && p.boosts.active) || 0,
        };
      };
      // keep the single deepest-liquidity pair per token address
      const bestPerToken = (pairs) => {
        const m = new Map();
        pairs.forEach(p => { const k = (p.baseToken && p.baseToken.address) || p.pairAddress; const cur = m.get(k); if (!cur || ((p.liquidity && p.liquidity.usd) || 0) > ((cur.liquidity && cur.liquidity.usd) || 0)) m.set(k, p); });
        return [...m.values()];
      };
      if (env.KV) { const hit = await env.KV.get(ck); if (hit) return new Response(hit, { headers: { 'Content-Type': 'application/json', 'X-Cache': 'kv' } }); }
      let out = [];
      try {
        if (type === 'trending') {
          const br = await fetch('https://api.dexscreener.com/token-boosts/top/v1', { headers: { 'User-Agent': 'DueDiligence/1.0' } });
          const boosts = await br.json();
          const seen = new Set(); const addrs = [];
          (Array.isArray(boosts) ? boosts : []).forEach(b => { const a = b.tokenAddress; if (a && !seen.has(a) && seen.size < 25) { seen.add(a); addrs.push(a); } });
          if (addrs.length) {
            const tr = await fetch('https://api.dexscreener.com/latest/dex/tokens/' + addrs.join(','), { headers: { 'User-Agent': 'DueDiligence/1.0' } });
            const td = await tr.json();
            out = bestPerToken(td.pairs || []).map(trim).filter(r => r.sym)
              .sort((a, b) => (b.boost - a.boost) || (b.vol - a.vol)).slice(0, 30);
          }
        } else if (type === 'token') {
          if (!addr) return json([]);
          const tr = await fetch('https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(addr), { headers: { 'User-Agent': 'DueDiligence/1.0' } });
          const td = await tr.json();
          out = (td.pairs || []).map(trim).filter(r => r.sym).sort((a, b) => b.liq - a.liq).slice(0, 15);
        } else { // search
          if (!q) return json([]);
          const sr = await fetch('https://api.dexscreener.com/latest/dex/search?q=' + encodeURIComponent(q), { headers: { 'User-Agent': 'DueDiligence/1.0' } });
          const sd = await sr.json();
          out = bestPerToken(sd.pairs || []).map(trim).filter(r => r.sym).sort((a, b) => b.liq - a.liq).slice(0, 40);
        }
      } catch {}
      const body = JSON.stringify(out);
      if (env.KV && out.length) ctx.waitUntil(env.KV.put(ck, body, { expirationTtl: type === 'trending' ? 120 : 60 }));
      return new Response(body, { headers: { 'Content-Type': 'application/json' } });
    }
    if (path.startsWith('/api/social/')) return social(request, env, user, url);
    if (path.startsWith('/api/')) return json({ error: 'not found' }, 404);

    return harden(await env.ASSETS.fetch(request));
}
