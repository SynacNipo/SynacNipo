# synacni-comments — guestbook API (Cloudflare Workers, free tier)

## Deploy (one time, ~10 min)

1. `npm i -g wrangler` then `wrangler login`
2. `wrangler kv namespace create KB` — paste the id into `wrangler.toml`
3. Secrets:
   - `wrangler secret put GITHUB_CLIENT_ID`
   - `wrangler secret put GITHUB_CLIENT_SECRET`
   - `wrangler secret put OWNER_GITHUB_USERNAME` (value: `SynacNipo`)
4. GitHub OAuth app: https://github.com/settings/developers → New OAuth App
   - Homepage URL: `https://synacnipo.github.io/SynacNipo/personal.html`
   - Callback URL: `https://synacni-comments.YOU.workers.dev/api/auth/callback`
   - use its Client ID + secret in step 3
5. `wrangler deploy` (from this folder)
6. Put the worker URL into `personal.html` (`API_BASE`), commit + push. Done.

## How it works

- Guests post name + comment, no login. One comment per IP every 5 min (429 otherwise).
- Owner clicks "login with github" → GitHub → back to the personal page with
  an owner session. Owner posts skip the rate limit and get a delete link
  under every comment. Anyone else hitting login gets a plain "owner only" page.
