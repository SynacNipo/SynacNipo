// Guestbook API for the synacni personal page. Runs on Cloudflare Workers (free).
// KV binding: KB.
// Secrets (wrangler secret put): GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, OWNER_GITHUB_USERNAME
// Vars (wrangler.toml): SITE_URL, ALLOWED_ORIGINS

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', ...extra } });

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const h = { Vary: 'Origin' };
  if (allowed.includes(origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Credentials'] = 'true';
  }
  return h;
}

function getSession(req) {
  const m = (req.headers.get('Cookie') || '').match(/(?:^|;\s*)sess=([A-Za-z0-9-]+)/);
  return m ? m[1] : null;
}

async function sessionData(req, env) {
  const tok = getSession(req);
  if (!tok) return null;
  const raw = await env.KB.get('sess:' + tok);
  if (!raw) return null;
  try {
    const o = JSON.parse(raw);
    if (o && o.login) return o;
  } catch {}
  return { login: raw, token: null }; // pre-token sessions: valid login, must re-login to post logs
}

function isOwnerLogin(login, env) {
  return !!login && login.toLowerCase() === (env.OWNER_GITHUB_USERNAME || '').toLowerCase();
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: { ...cors, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
    }
    const withCors = (r) => {
      const h = new Headers(r.headers);
      for (const [k, v] of Object.entries(cors)) h.set(k, v);
      return new Response(r.body, { status: r.status, headers: h });
    };

    // list comments, newest first
    if (url.pathname === '/api/comments' && req.method === 'GET') {
      const list = JSON.parse((await env.KB.get('comments')) || '[]');
      return withCors(json({ comments: list.slice(0, 100) }));
    }

    // post a comment — guests rate-limited to 1 per 5 min, owner exempt
    if (url.pathname === '/api/comments' && req.method === 'POST') {
      const sess = await sessionData(req, env);
      const login = sess && sess.login;
      const owner = isOwnerLogin(login, env);
      let body;
      try { body = await req.json(); } catch { return withCors(json({ error: 'bad json' }, 400)); }
      let name = String(body.name || '').slice(0, 30).trim();
      const text = String(body.body || '').slice(0, 500).trim();
      if (!text) return withCors(json({ error: 'comment is empty' }, 400));
      if (!name) name = owner ? login : 'Guest-' + Math.floor(1000 + Math.random() * 9000);
      const parent = String(body.parent || '').slice(0, 32) || null;
      if (!owner) {
        const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
        if (await env.KB.get('rl:' + ip))
          return withCors(json({ error: 'slow down — one comment every 5 minutes' }, 429));
        await env.KB.put('rl:' + ip, '1', { expirationTtl: 300 });
      }
      const list = JSON.parse((await env.KB.get('comments')) || '[]');
      if (parent && !list.some((c) => c.id === parent && !c.parent))
        return withCors(json({ error: 'thread not found' }, 400));
      const entry = {
        id: Date.now().toString(36) + Math.floor(Math.random() * 1e6).toString(36),
        name, body: text, at: new Date().toISOString(), owner, parent,
      };
      list.unshift(entry);
      await env.KB.put('comments', JSON.stringify(list.slice(0, 200)));
      return withCors(json({ ok: true, comment: entry }));
    }

    // delete a comment — owner only
    const del = url.pathname.match(/^\/api\/comments\/([A-Za-z0-9]+)\/delete$/);
    if (del && req.method === 'POST') {
      const sess = await sessionData(req, env);
      const login = sess && sess.login;
      if (!isOwnerLogin(login, env)) return withCors(json({ error: 'owner only' }, 403));
      const list = JSON.parse((await env.KB.get('comments')) || '[]');
      await env.KB.put('comments', JSON.stringify(list.filter((c) => c.id !== del[1] && c.parent !== del[1])));
      return withCors(json({ ok: true }));
    }

    // add a personal log entry — owner only, commits to the repo via the api
    if (url.pathname === '/api/log' && req.method === 'POST') {
      const sess = await sessionData(req, env);
      const login = sess && sess.login;
      if (!isOwnerLogin(login, env)) return withCors(json({ error: 'owner only' }, 403));
      if (!sess.token) return withCors(json({ error: 'please log in again' }, 403));
      let body;
      try { body = await req.json(); } catch { return withCors(json({ error: 'bad json' }, 400)); }
      const text = String(body.body || '').slice(0, 2000).trim();
      if (!text) return withCors(json({ error: 'entry is empty' }, 400));
      const repo = env.LOG_REPO || 'SynacNipo/SynacNipo';
      const path = env.LOG_PATH || 'things/log.json';
      const branch = env.LOG_BRANCH || 'main';
      const gh = (u, opts = {}) => fetch('https://api.github.com' + u, {
        ...opts,
        headers: { Authorization: 'Bearer ' + sess.token, 'User-Agent': 'synacni-comments', Accept: 'application/vnd.github+json', ...(opts.headers || {}) },
      });
      const cur = await gh('/repos/' + repo + '/contents/' + path + '?ref=' + branch);
      if (!cur.ok) return withCors(json({ error: 'could not read log file' }, 500));
      const curJ = await cur.json();
      let data;
      try { data = JSON.parse(atob(curJ.content.replace(/\n/g, ''))); } catch { return withCors(json({ error: 'log file is corrupt' }, 500)); }
      data.entries = data.entries || [];
      data.entries.push({ date: new Date().toISOString(), body: text });
      const updated = btoa(unescape(encodeURIComponent(JSON.stringify(data, null, 2))));
      const put = await gh('/repos/' + repo + '/contents/' + path, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'Add personal log entry', content: updated, sha: curJ.sha, branch }),
      });
      if (!put.ok) return withCors(json({ error: 'commit failed' }, 500));
      return withCors(json({ ok: true }));
    }

    // owner login via github
    if (url.pathname === '/api/auth/login') {
      const state = crypto.randomUUID();
      await env.KB.put('oauth:' + state, '1', { expirationTtl: 600 });
      const redirect = 'https://github.com/login/oauth/authorize?client_id=' + encodeURIComponent(env.GITHUB_CLIENT_ID)
        + '&redirect_uri=' + encodeURIComponent(new URL('/api/auth/callback', url.origin).toString())
        + '&state=' + state + '&scope=repo';
      return Response.redirect(redirect, 302);
    }

    // github oauth callback — only the owner gets a session, anyone else gets told no
    if (url.pathname === '/api/auth/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state || !(await env.KB.get('oauth:' + state)))
        return new Response('bad oauth state', { status: 400 });
      await env.KB.delete('oauth:' + state);
      const tokRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code }),
      });
      const tok = await tokRes.json();
      if (!tok.access_token) return new Response('github auth failed', { status: 403 });
      const uRes = await fetch('https://api.github.com/user', {
        headers: { Authorization: 'Bearer ' + tok.access_token, 'User-Agent': 'synacni-comments' },
      });
      const u = await uRes.json();
      if (!isOwnerLogin(u.login, env))
        return new Response('owner login only — guests just comment below, no login needed.', { status: 403, headers: { 'content-type': 'text/plain' } });
      const sess = crypto.randomUUID();
      await env.KB.put('sess:' + sess, JSON.stringify({ login: u.login, token: tok.access_token }), { expirationTtl: 30 * 86400 });
      const headers = new Headers({ Location: env.SITE_URL || '/' });
      headers.append('Set-Cookie', 'sess=' + sess + '; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=' + 30 * 86400);
      return new Response(null, { status: 302, headers });
    }

    // who am i
    if (url.pathname === '/api/auth/me') {
      const sess = await sessionData(req, env);
      const login = sess && sess.login;
      if (!login) return withCors(json({ user: null }, 401));
      return withCors(json({ user: login, owner: isOwnerLogin(login, env) }));
    }

    return withCors(json({ error: 'not found' }, 404));
  },
};
