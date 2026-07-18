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
// client bundle (service role, API keys, tokens, credentials, LLM-provider keys,
// a bare DATABASE_URL, an APIKEY with no separator).
// The LLM vendors are matched as `<vendor>_?KEY` (never a bare `_KEY`, so a public
// app key like PUSHER_KEY or a Supabase ANON_KEY is not swept in by accident).
// Every alternative is trailing-anchored with (?![A-Z0-9]) so a secret WORD only
// matches as a whole token — `TOKEN` must not match inside `TOKENIZER`, nor `KEY`
// inside `KEYCLOAK` — which is how public config (`SERVER_TOKENIZER_URL`) used to
// be flagged by mistake. (Suffix is camel-split then upper-cased before testing —
// see scanSecrets/normalizeSuffix — so `apiKey` → `API_KEY` and `databaseUrl` →
// `DATABASE_URL` are matched. DATABASE_URL stays in SECRETY, not HARD_SECRET, so a
// genuinely public one — Firebase's `NEXT_PUBLIC_FIREBASE_DATABASE_URL` — is still
// waved through by PUBLIC_OK, while a bare Postgres URL is caught.)
// NOTE: the suffix is CANONICALIZED before these match — camelCase split AND all
// separators removed (see canonicalSuffix), so patterns are separator-free and a
// glued spelling collapses to the same token as the snake one: `serviceRoleKey`,
// `SERVICE_ROLE_KEY` and `SERVICEROLEKEY` all become `SERVICEROLEKEY`. That's why
// each token is written glued (SERVICEROLE, APIKEY) and absorbs an optional trailing
// KEY/TOKEN, all trailing-anchored with (?![A-Z0-9]) so `TOKEN` won't match inside
// `TOKENIZER` nor `KEY` inside `KEYCLOAK`.
export const SECRETY = /(?:SERVICEROLE|SERVICEKEY|APIKEY|ACCESSKEY|DATABASEURL|(?:SECRET|PRIVATE)(?:KEY|TOKEN)?|PASSWORD|PASSWD|CREDENTIAL|TOKEN|ENCRYPTION|SIGNING|(?:ANTHROPIC|OPENAI|OPENROUTER|GROQ|MISTRAL|COHERE|REPLICATE|HUGGINGFACE|PERPLEXITY|DEEPSEEK|TOGETHER|GEMINI|XAI)KEY)(?![A-Z0-9])/
// Strong secret words the PUBLIC_OK allow-list must NEVER wave through — even on a
// vendor whose other NEXT_PUBLIC_ keys are public (FIREBASE_PRIVATE_KEY,
// ALGOLIA_ADMIN_KEY, FIREBASE_ADMIN_TOKEN, ALGOLIA_MASTER_KEY). `ADMIN_(KEY|TOKEN)`
// and `MASTER_KEY` are admin/root credentials by any vendor — a real leak — but
// plain ADMIN_URL / ADMIN_EMAIL is not, so we require the KEY/TOKEN suffix rather
// than a bare ADMIN.
// `ADMIN_KEY`/`SERVER_TOKEN`/`MASTER_KEY` are anchored with (?![A-Z0-9]) so they
// match the whole word — NOT a substring of legit public config like
// `ADMIN_KEYCLOAK_URL` or `SERVER_TOKENIZER_URL` (which are not secrets). Suffix is
// camel-split then upper-cased before testing (see scanSecrets/normalizeSuffix), so
// these patterns stay case-normalized and `masterKey` → `MASTER_KEY` is caught.
// Canonicalized (separator-free) too. Standalone strong words absorb an optional
// glued KEY/TOKEN (`SECRETKEY`, `PRIVATEKEY`, `SERVICEROLEKEY`). ADMIN/SERVER/MASTER
// REQUIRE a KEY/TOKEN so a bare `ADMIN` / `ADMIN_URL` (→ ADMINURL) is not flagged.
const HARD_SECRET = /(?:(?:SERVICEROLE|PRIVATE|PASSWORD|PASSWD|SECRET|SIGNING|ENCRYPTION|CREDENTIAL)(?:KEY|TOKEN)?|(?:ADMIN|SERVER|MASTER)(?:KEY|TOKEN))(?![A-Z0-9])/
// …names that look scary but are public by design: anon / publishable / site keys,
// analytics IDs, client-SDK config (Firebase, Google Maps, web-push VAPID), and
// public client tokens/keys of common realtime/analytics/error SDKs. A CLIENT_TOKEN
// (e.g. Paddle's — the stack ShipSealed itself sells on) is public by design; a
// CLIENT_SECRET is not, and stays caught by HARD_SECRET.
// Canonicalized (separator-free) — matches the same de-separated suffix. Left
// lenient (no trailing anchor) because these are EXEMPTIONS and HARD_SECRET is
// checked first, so a real secret on a "public" vendor (FIREBASE_PRIVATE_KEY,
// ALGOLIA_ADMIN_KEY) is still caught regardless of a PUBLIC_OK match.
const PUBLIC_OK = /ANON|PUBLISHABLE|SITEKEY|CLIENTID|CLIENTTOKEN|MEASUREMENTID|MAPBOX|MAPS|TURNSTILE|RECAPTCHA|HCAPTCHA|ALGOLIA|POSTHOG|FIREBASE|VAPID|STREAMAPIKEY|GETSTREAM|LIVEKIT|LIVEBLOCKSPUBLIC|SEGMENTWRITE|SENTRYDSN/

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

// Normalize a NEXT_PUBLIC_ suffix to screaming-snake before matching. Next.js
// only inlines the exact `NEXT_PUBLIC_` prefix, but the SUFFIX is author-chosen and
// may be any case — INCLUDING camelCase with no separators (NEXT_PUBLIC_serviceRoleKey).
// A plain .toUpperCase() would turn that into `SERVICEROLEKEY`, which no snake_case
// pattern (SERVICE_ROLE, API_KEY, …) can match — the exact bypass that let a real
// secret slip through. So we first split camelCase boundaries into underscores
// (`serviceRoleKey` → `service_Role_Key`, `apiKey` → `api_Key`) and THEN upper-case,
// yielding `SERVICE_ROLE_KEY` / `API_KEY` — matched by the same patterns as the
// screaming-case spelling. Matching is therefore case-insensitive on the suffix.
function canonicalSuffix(s) {
  return s
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2') // split camelCase (serviceRoleKey → service_Role_Key)
    .toUpperCase()
    .replace(/[_-]/g, '') // then drop ALL separators → one canonical glued form
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
  // The NEXT_PUBLIC_ prefix must be exact (Next.js only inlines that spelling),
  // but the SUFFIX may be any case AND any separator style — camelCase, snake,
  // kebab (`service-role-key`), or ALL-CAPS glued with none (`SERVICEROLEKEY`). A
  // secret in any of those spellings is still a real leak, so canonicalSuffix folds
  // them all to one form before matching. The extraction class MUST include `-` too,
  // or a kebab name is truncated at the first hyphen before canonicalSuffix ever
  // sees it (the exact gap that let `NEXT_PUBLIC_service-role-key` slip through).
  const re = /NEXT_PUBLIC_[A-Za-z0-9_-]+/g
  let m
  while ((m = re.exec(text))) {
    const name = m[0]
    const suffix = canonicalSuffix(name.slice('NEXT_PUBLIC_'.length))
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

// A file (or function) marked `'use server'` exposes its exported functions as
// client-callable mutation entry points — the SAME trust boundary as a route
// handler, but reachable directly from a form/RPC. A read-only action stays silent;
// one that performs a DB write with no auth check flags `unauth_server_action`
// (warn), mirroring scanRoute. Write signals: a Supabase mutation
// (.insert/.update/.delete/.upsert) or raw INSERT/UPDATE/DELETE.
// The directive as its OWN statement (file-level or fn-level), never a string value
// — so `const label = "use server"` or a doc example doesn't turn a file into an action.
const USE_SERVER = /^\s*(['"])use server\1\s*;?\s*$/m
// A DB write, ANCHORED to a real database handle so a same-named method on
// cookies()/formData/headers()/a Map (`cookies().delete('session')` in a logout) is
// NOT mistaken for one — that false alarm is the whole thing this product refuses:
//  - Supabase / knex:  `.from(...) … .insert/.update/.delete/.del/.upsert(`
//  - Drizzle:          `db.insert/.update/.delete(`
//  - Prisma:           `prisma.model.create/update/delete/upsert(` (+ *Many)
//  - raw SQL:          INSERT INTO / UPDATE … SET / DELETE FROM
// The write method must be in the SAME method chain as `.from(...)` / `knex(...)` —
// `(?:\s*\.\w+\([^)]*\))*?` walks only continuous `.foo(...)` links, so it can't hop a
// `;`/new statement to a `.delete(` on cookies()/formData() sitting nearby. That
// "read, then clear a cookie" shape is common and must stay silent.
const DB_WRITE_PATTERNS = [
  /\.from\([^)]*\)(?:\s*\.\w+\([^)]*\))*?\s*\.(?:insert|update|delete|del|upsert)\s*\(/i, // supabase/knex .from('t')…write
  /\bknex\([^)]*\)(?:\s*\.\w+\([^)]*\))*?\s*\.(?:insert|update|delete|del)\s*\(/i,        // knex('t')…write
  /\bdb\.(?:insert|update|delete)\s*\(/i,                                                 // drizzle
  /\bprisma\.\w+\.(?:create|createMany|update|updateMany|delete|deleteMany|upsert)\s*\(/i, // prisma
  // raw SQL, but ONLY where it's actually EXECUTED — a SQL tagged template
  // (sql`…`, db`…`, prisma.$executeRaw`…`) or a .query()/.execute()/.raw()/.unsafe()
  // call — so an English phrase in a toast/error string ("delete from your list")
  // is NOT mistaken for a write.
  /\b(?:sql|db|pool|client|conn|connection|executeRaw|queryRaw)\s*`[^`]*?\b(?:insert\s+into|update\s+[\w."]+\s+set|delete\s+from)\b/i,
  /\.(?:query|execute|executeRaw|raw|unsafe|prepare)\s*\(\s*[`'"][^`'"]*?\b(?:insert\s+into|update\s+[\w."]+\s+set|delete\s+from)\b/i,
]
function dbWrite(text) {
  for (const re of DB_WRITE_PATTERNS) {
    const m = re.exec(text)
    if (m) return m
  }
  return null
}

const EXPORT_FN = /export\s+(?:async\s+)?function\s+\w+|export\s+(?:const|let|var)\s+\w+\s*=/g

export function scanServerAction(rawText, file, { authFns = [] } = {}) {
  const text = stripJsComments(rawText)
  if (!USE_SERVER.test(text)) return [] // not a Server Action file
  const authRe = authFns.length ? new RegExp(`${AUTH.source}|${authFns.map(escapeRe).join('|')}`, 'i') : AUTH
  // Slice the file into exported-function segments so an auth call in ONE action
  // doesn't clear an unauthed write in ANOTHER (the file-level false negative).
  // Each segment runs from one `export … function/const` to the next.
  const starts = []
  let e
  EXPORT_FN.lastIndex = 0
  while ((e = EXPORT_FN.exec(text))) starts.push(e.index)
  const segments = starts.length ? starts.map((s, i) => [s, starts[i + 1] ?? text.length]) : [[0, text.length]]
  const out = []
  const seen = new Set()
  for (const [a, b] of segments) {
    const seg = text.slice(a, b)
    const write = dbWrite(seg)
    if (!write) continue // this action does no DB write → nothing to guard
    if (authRe.test(seg)) continue // this action authenticates → clean
    const line = lineOf(text, a + write.index)
    if (seen.has(line)) continue
    seen.add(line)
    out.push({ rule: 'unauth_server_action', severity: 'warn', file, line, object: file, detail: `Server Action ('use server') writes to the database with no auth check — a Server Action is a client-callable mutation entry point, so confirm the caller is authorized (getUser/getSession/auth or your auth helper), or allow-list it if it is intentionally public.` })
  }
  return out
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
