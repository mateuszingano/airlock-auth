// Auth Route Guard rules — static lint of a Next.js (App Router) project.
//
// No build, no runtime. We read your source and flag the three auth mistakes
// that ship data leaks in Next+Supabase apps:
//   public_secret      (fail)  a server secret exposed via NEXT_PUBLIC_*
//   unauth_mutation    (warn)  a mutating route handler with no auth check
//   unverified_webhook (warn)  a webhook route that never verifies a signature
//
// Ethos (inherited from airlock-rls): a false positive is the #1 adoption
// killer. We only flag NEXT_PUBLIC_ names that clearly hold a secret (never the
// anon key or URL), we skip GET/read handlers, and a webhook route is judged on
// its signature check, not on "missing auth".
//
// Every finding is { rule, severity: 'fail'|'warn', file, line, object, detail }.

// NEXT_PUBLIC_* suffixes that mean "this is a server secret" — never safe in the
// client bundle (service role, API keys, tokens, credentials, LLM-provider keys).
// The LLM vendors are matched as `<vendor>_?KEY` (never a bare `_KEY`, so a public
// app key like PUSHER_KEY or a Supabase ANON_KEY is not swept in by accident).
export const SECRETY = /SERVICE_ROLE|SERVICE_KEY|SECRET|PRIVATE|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL|TOKEN|ENCRYPTION|SIGNING|(?:ANTHROPIC|OPENAI|OPENROUTER|GROQ|MISTRAL|COHERE|REPLICATE|HUGGINGFACE|PERPLEXITY|DEEPSEEK|TOGETHER|GEMINI|XAI)_?KEY/
// Strong secret words the PUBLIC_OK allow-list must NEVER wave through — even on a
// vendor whose other NEXT_PUBLIC_ keys are public (FIREBASE_PRIVATE_KEY,
// ALGOLIA_ADMIN_KEY, FIREBASE_ADMIN_TOKEN). `ADMIN_(KEY|TOKEN)` is admin
// credentials by any vendor — a real leak — but plain ADMIN_URL / ADMIN_EMAIL is
// not, so we require the KEY/TOKEN suffix rather than a bare ADMIN.
const HARD_SECRET = /SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|SECRET|SIGNING|ENCRYPTION|CREDENTIAL|(?:ADMIN|SERVER)[_-]?(?:KEY|TOKEN)/
// …names that look scary but are public by design: anon / publishable / site keys,
// analytics IDs, client-SDK config (Firebase, Google Maps, web-push VAPID), and
// public client tokens/keys of common realtime/analytics/error SDKs. A CLIENT_TOKEN
// (e.g. Paddle's — the stack ShipSealed itself sells on) is public by design; a
// CLIENT_SECRET is not, and stays caught by HARD_SECRET.
const PUBLIC_OK = /ANON|PUBLISHABLE|SITE_KEY|CLIENT_ID|CLIENT_TOKEN|MEASUREMENT_ID|MAPBOX|MAPS|TURNSTILE|RECAPTCHA|HCAPTCHA|ALGOLIA|POSTHOG|FIREBASE|VAPID|STREAM_API_KEY|GETSTREAM|LIVEKIT|LIVEBLOCKS_PUBLIC|SEGMENT_WRITE|SENTRY_DSN/

// A mutating export in an App Router route handler.
const MUTATION = /(?:export\s+(?:async\s+)?function\s+|export\s+const\s+)(POST|PUT|PATCH|DELETE)\b/g

// Signals that the handler actually authenticates the caller. Covers the inline
// Supabase/Clerk/NextAuth calls AND the far more common pattern of a centralized
// helper (requireUser, resolverAcessoEscrita, ensureSession, guardRoute, ...).
// This heuristic is what keeps the tool from crying wolf on a hardened app.
// Explicit calls are precise; the trailing group matches centralized helpers
// (requireUser, resolverAcessoEscrita, ensureSession…). NOTE: a bare `get` prefix
// is deliberately NOT in that group — it would treat getUserAgent / getUserId
// (a header read / a lookup) as auth and miss a real unguarded route.
//
// ReDoS-safe: the helper alternation is anchored at a word boundary and the gap
// between the prefix and the auth-noun is bounded to \w{0,40} (was an unbounded
// \w*). Unbounded, a long run of word-chars with no trailing noun backtracked
// catastrophically — measured O(n²): 240KB→7.5s, 960KB→143s. The bound makes
// per-position work constant; scan.mjs also caps file size (see MAX_FILE_BYTES).
const AUTH = /getUser\s*\(|getSession\s*\(|getServerSession|currentUser\s*\(|getAuth\s*\(|\bauth\s*\(\s*\)|isAuthenticated|getToken\s*\(|\.auth\b|\b(?:require|ensure|assert|check|verify|resolve|guard|with)\w{0,40}(?:Auth|User|Session|Access|Acesso|Permiss|Autoriz|Membro|Owner|Login|Ident|Escrita)/i

// Signals that a webhook verifies its payload signature.
const SIGVERIFY = /signature|verif(?:y|ied|ication)|hmac|constructEvent|svix|createHmac|timingSafeEqual|paddle-signature|stripe-signature/i

function norm(p) {
  return p.replace(/\\/g, '/')
}

// Strip JS/TS comments so a comment ("// TODO: verify signature") can't fake a
// signal — while keeping STRING contents intact (a `//` inside "https://..." or
// "//cdn" is not a comment, and must not swallow a secret on the same line) and
// preserving newlines so line numbers stay accurate. A tiny scanner that tracks
// ' " ` strings with escapes; regex-literal edge cases are out of scope.
export function stripJsComments(src) {
  let out = ''
  let i = 0
  const n = src.length
  let q = null // current string quote char, or null
  while (i < n) {
    const c = src[i]
    const c2 = src[i + 1]
    if (q) {
      if (c === '\\') { out += c + (c2 ?? ''); i += 2; continue } // keep escapes
      if (c === q) { q = null; out += c; i++; continue }
      out += c
      i++
      continue
    }
    if (c === '/' && c2 === '/') {
      while (i < n && src[i] !== '\n') { out += ' '; i++ }
      continue
    }
    if (c === '/' && c2 === '*') {
      out += '  '; i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { out += src[i] === '\n' ? '\n' : ' '; i++ }
      if (i < n) { out += '  '; i += 2 }
      continue
    }
    if (c === "'" || c === '"' || c === '`') { q = c; out += c; i++; continue }
    out += c
    i++
  }
  return out
}

export function isRouteFile(path) {
  return /(?:^|\/)app\/(?:.*\/)?route\.(?:t|j)sx?$/.test(norm(path))
}

export function isEnvFile(path) {
  return /(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(norm(path))
}

export function isSourceFile(path) {
  return /\.(?:t|j)sx?$|\.mjs$|\.cjs$/.test(norm(path))
}

// Pages Router API route — pages/api/**.ts (a lot of real Next apps still use it),
// excluding _-prefixed files (_middleware, _document, …).
export function isPagesApiFile(path) {
  const p = norm(path)
  return /(?:^|\/)(?:src\/)?pages\/api\/.*\.(?:t|j)sx?$/.test(p) && !/(?:^|\/)_[^/]*\.(?:t|j)sx?$/.test(p)
}

/** app/api/webhooks/paddle/route.ts → /api/webhooks/paddle */
export function routeUrl(path) {
  const p = norm(path)
  const m = /(?:^|\/)app\/(.*)\/route\.(?:t|j)sx?$/.exec(p)
  if (!m) return p
  return '/' + m[1].replace(/\/?\(.*?\)/g, '').replace(/^\/+/, '') // strip route groups (auth)
}

/** pages/api/charge.ts → /api/charge · pages/api/user/index.ts → /api/user */
export function pagesRouteUrl(path) {
  const p = norm(path)
  const m = /(?:^|\/)(?:src\/)?pages\/api\/(.*)\.(?:t|j)sx?$/.exec(p)
  if (!m) return p
  return '/api/' + m[1].replace(/\/index$/, '')
}

function lineOf(text, index) {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++
  return line
}

/** Flag NEXT_PUBLIC_* names that hold a secret. Returns findings (deduped per file). */
export function scanSecrets(rawText, file) {
  const text = stripJsComments(rawText)
  const out = []
  const seen = new Set()
  const re = /NEXT_PUBLIC_[A-Z0-9_]+/g
  let m
  while ((m = re.exec(text))) {
    const name = m[0]
    const suffix = name.slice('NEXT_PUBLIC_'.length)
    if (seen.has(name)) continue
    // A hard secret is always flagged; a softer signal (API key / token / LLM key)
    // is flagged unless the name matches a known-public pattern (anon, publishable…).
    const isSecret = HARD_SECRET.test(suffix) || (SECRETY.test(suffix) && !PUBLIC_OK.test(suffix))
    if (!isSecret) continue
    seen.add(name)
    out.push({ rule: 'public_secret', severity: 'fail', file, line: lineOf(text, m.index), object: name, detail: `${name} is inlined into the client bundle by Next.js — a "NEXT_PUBLIC_" secret is readable by anyone. Rename it (drop NEXT_PUBLIC_) and read it server-side only.` })
  }
  return out
}

/**
 * Judge one App Router route file.
 * @param {string} text  file contents
 * @param {string} file  path (used for the URL + webhook classification)
 * @param {{authFns?: string[]}} opts  extra auth-helper names this project uses
 */
export function scanRoute(rawText, file, { authFns = [] } = {}) {
  const text = stripJsComments(rawText)
  const out = []
  const url = routeUrl(file)
  const methods = []
  let m
  MUTATION.lastIndex = 0
  while ((m = MUTATION.exec(text))) methods.push({ method: m[1], line: lineOf(text, m.index) })

  // A route is a webhook only by its PATH — never by merely mentioning the word
  // (a checkout route that references its webhook URL is not itself a webhook).
  const isWebhook = /webhook/i.test(norm(file))

  if (isWebhook) {
    if (!SIGVERIFY.test(text)) {
      out.push({ rule: 'unverified_webhook', severity: 'warn', file, line: methods[0]?.line || 1, object: url, detail: `webhook route with no signature verification — anyone who finds the URL can forge calls. Verify the provider signature before trusting the body.` })
    }
    return out
  }

  const authRe = authFns.length ? new RegExp(`${AUTH.source}|${authFns.map(escapeRe).join('|')}`, 'i') : AUTH
  if (methods.length && !authRe.test(text)) {
    const names = [...new Set(methods.map((x) => x.method))].join('/')
    out.push({ rule: 'unauth_mutation', severity: 'warn', file, line: methods[0].line, object: `${names} ${url}`, detail: `mutating handler with no auth check — confirm the caller is authorized (getUser/getSession/auth or your auth helper), or allow-list it if it is intentionally public.` })
  }
  return out
}

// A Pages Router handler ships one default export and switches on `req.method`,
// so we flag it only when it EXPLICITLY handles a mutating method (a GET-only
// handler stays silent). Webhooks are judged on the signature, same as App Router.
const PAGES_MUTATION = /(?:req\.method\s*===?\s*|case\s+)['"`](post|put|patch|delete)['"`]/i

export function scanPagesRoute(rawText, file, { authFns = [] } = {}) {
  const text = stripJsComments(rawText)
  const out = []
  const url = pagesRouteUrl(file)
  const isWebhook = /webhook/i.test(norm(file))

  if (isWebhook) {
    if (!SIGVERIFY.test(text)) {
      out.push({ rule: 'unverified_webhook', severity: 'warn', file, line: 1, object: url, detail: `webhook route with no signature verification — anyone who finds the URL can forge calls. Verify the provider signature before trusting the body.` })
    }
    return out
  }

  const mut = PAGES_MUTATION.exec(text)
  if (!mut) return out // GET-only or no explicit mutating method → not flagged

  const authRe = authFns.length ? new RegExp(`${AUTH.source}|${authFns.map(escapeRe).join('|')}`, 'i') : AUTH
  if (!authRe.test(text)) {
    out.push({ rule: 'unauth_mutation', severity: 'warn', file, line: lineOf(text, mut.index), object: `${url} (pages)`, detail: `mutating handler with no auth check — confirm the caller is authorized (getUser/getSession/auth or your auth helper), or allow-list it if it is intentionally public.` })
  }
  return out
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
