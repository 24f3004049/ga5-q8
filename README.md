# agent-guardrail

A guardrail endpoint in front of `read_file(path)` and `fetch_url(url)`.

- `POST /api/guardrail` with `{ "tool": "read_file", "arguments": { "path": "..." } }`
  or `{ "tool": "fetch_url", "arguments": { "url": "..." } }`
- Returns `{ "action": "allow"|"block", "reason": "...", "result": ... }`

## 1. What's in this project

```
guardrail-vercel/
  api/
    guardrail.js        <- the guardrail logic + HTTP handler (this is the whole endpoint)
  data/
    sandbox/
      notes/report.txt
      notes/looks-like-..-but-safe.txt
      encoded/%2e%2e-literal.txt
    outside/
      canary.txt         <- deliberately outside the sandbox, must never be reachable
  vercel.json             <- tells Vercel to bundle data/** with the function
  package.json
  README.md
```

`api/guardrail.js` is a standard Vercel Node.js Serverless Function. Any file
under `/api` automatically becomes a route at `/api/<filename>`, so this
becomes **`/api/guardrail`** once deployed — no extra routing config needed.

The `data/` folder ships as part of the deployment bundle (via
`vercel.json`'s `includeFiles`) so the sandbox files really exist on the
machine the function runs on, exactly as the task requires. The code never
reads anything under `data/outside/`; it's only there to satisfy "create
these files on the machine" and to prove the canary can't be reached.

## 2. Deploy to Vercel

### Option A — Vercel CLI (fastest)

```bash
npm i -g vercel          # if you don't have it already
cd guardrail-vercel
vercel login             # opens a browser to authenticate
vercel --prod            # deploys straight from this folder
```

Answer the prompts:
- "Set up and deploy?" → Yes
- "Which scope?" → pick your account/team
- "Link to existing project?" → No (first time)
- "What's your project's name?" → e.g. `agent-guardrail`
- "In which directory is your code located?" → `./`
- Framework preset → **Other** (no framework needed)
- Override build/output settings → No

Vercel prints a URL like:

```
https://agent-guardrail-xxxxx.vercel.app
```

Your graded endpoint URL is:

```
https://agent-guardrail-xxxxx.vercel.app/api/guardrail
```

Every subsequent `vercel --prod` from this folder redeploys the same project.

### Option B — GitHub + Vercel dashboard

1. Push this folder to a new GitHub repo:
   ```bash
   cd guardrail-vercel
   git init
   git add -A
   git commit -m "agent guardrail endpoint"
   git branch -M main
   git remote add origin https://github.com/<you>/agent-guardrail.git
   git push -u origin main
   ```
2. Go to https://vercel.com/new, import the repo.
3. Framework preset: **Other**. Leave build command / output directory blank
   (nothing to build — it's just an API route).
4. Click **Deploy**.
5. Your endpoint is `https://<project-name>.vercel.app/api/guardrail`.

No environment variables or secrets are required.

## 3. Verify the deployment before submitting

```bash
BASE="https://agent-guardrail-xxxxx.vercel.app"

# health check
curl -s "$BASE/api/guardrail" | head -c 300; echo

# benign read inside sandbox
curl -s -X POST "$BASE/api/guardrail" -H 'Content-Type: application/json' \
  -d '{"tool":"read_file","arguments":{"path":"notes/report.txt"}}'; echo

# malicious traversal to canary — must be blocked, must never show the canary token
curl -s -X POST "$BASE/api/guardrail" -H 'Content-Type: application/json' \
  -d '{"tool":"read_file","arguments":{"path":"../outside-05aa34a3/canary.txt"}}'; echo

# benign fetch to an allowed host
curl -s -X POST "$BASE/api/guardrail" -H 'Content-Type: application/json' \
  -d '{"tool":"fetch_url","arguments":{"url":"https://example.com/"}}'; echo

# malicious SSRF to cloud metadata IP — must be blocked
curl -s -X POST "$BASE/api/guardrail" -H 'Content-Type: application/json' \
  -d '{"tool":"fetch_url","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}'; echo

# malicious SSRF via redirect-style param on an allowed host — must be blocked
curl -s -X POST "$BASE/api/guardrail" -H 'Content-Type: application/json' \
  -d '{"tool":"fetch_url","arguments":{"url":"https://example.com/redirect?next=http://169.254.169.254/"}}'; echo
```

Expected: the three benign calls return `"action":"allow"` with real content/
body; the three malicious calls return `"action":"block"` and never contain
`AGENT_GUARDRAIL_CANARY_742ccf6b8036b7671c14f78d93745170b9ace3f6`.

If a request fails, check the response for an `x-deny-reason`-style hint, or
run `vercel logs <deployment-url>` to see server-side errors.

## 4. How the logic works (short version)

**read_file** — the requested `path` is resolved as if it lived inside the
logical sandbox root `/srv/agent-redteam/sandbox-6674332e2d` (relative paths
are joined onto that root; absolute paths are used as-is), then
`path.posix.normalize`d. The result is only allowed if it equals the root or
starts with `root + "/"` — a prefix check that also guards against the
classic `sandbox-XXXXevil` prefix-confusion bug. Path arguments are **never**
percent-decoded, so a literal filename like `%2e%2e-literal.txt` is just a
filename, not a traversal sequence.

**fetch_url** — the URL is parsed with the WHATWG `URL` class (which
correctly resolves userinfo-confused URLs like `http://good.com@evil/` to
their real host), the scheme must be `http`/`https`, and the resolved
hostname must exactly match the allow-list (`example.com`, `www.iana.org`)
case-insensitively, trailing-dot normalized. Even when the host is allowed,
the path/query/fragment are scanned for embedded internal targets — raw
private/loopback/link-local/metadata IPs, `localhost`, or a nested URL
pointing somewhere off the allow-list — which is what stops
`example.com/redirect?next=<internal>`. Redirects are never auto-followed
(`redirect: 'manual'`), so a same-host response that tries to 302 you
somewhere internal doesn't get silently followed either.

## 5. Keeping it live

The task says the endpoint must stay deployed and configured through the
grading deadline. Vercel deployments from `vercel --prod` / a connected Git
repo stay up indefinitely with no extra action — just don't delete the
project or remove the GitHub integration before grading finishes.
