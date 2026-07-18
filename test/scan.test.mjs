import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { writeFile, rm, mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scanSecrets, scanRoute, scanPagesRoute, scanServerAction, isRouteFile, isPagesApiFile, routeUrl, pagesRouteUrl } from '../src/rules.mjs'
import { scan } from '../src/scan.mjs'
import { levelOf, fixFor, enrich, toMarkdown } from '../src/report.mjs'

const fxDir = fileURLToPath(new URL('../fixtures', import.meta.url))

// ---- scanSecrets ----
test('NEXT_PUBLIC_ service role key is a fail', () => {
  const f = scanSecrets('const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'a.ts')
  assert.equal(f.length, 1)
  assert.equal(f[0].rule, 'public_secret')
  assert.equal(f[0].severity, 'fail')
})

test('NEXT_PUBLIC_ anon key and URL are NOT flagged', () => {
  const f = scanSecrets('a=NEXT_PUBLIC_SUPABASE_ANON_KEY; b=NEXT_PUBLIC_SUPABASE_URL', 'a.ts')
  assert.equal(f.length, 0)
})

test('a NEXT_PUBLIC_ secret is flagged once, not per occurrence', () => {
  const f = scanSecrets('NEXT_PUBLIC_STRIPE_SECRET NEXT_PUBLIC_STRIPE_SECRET', 'a.ts')
  assert.equal(f.length, 1)
})

test('API keys and tokens are caught, not just SECRET/SERVICE_ROLE', () => {
  for (const name of ['NEXT_PUBLIC_OPENAI_API_KEY', 'NEXT_PUBLIC_GITHUB_TOKEN', 'NEXT_PUBLIC_API_TOKEN', 'NEXT_PUBLIC_AWS_ACCESS_KEY']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} flagged`)
  }
})

test('bare-KEY provider secrets (ANTHROPIC_KEY, ENCRYPTION_KEY, SIGNING_KEY) are caught', () => {
  for (const name of ['NEXT_PUBLIC_ANTHROPIC_KEY', 'NEXT_PUBLIC_OPENAI_KEY', 'NEXT_PUBLIC_ENCRYPTION_KEY', 'NEXT_PUBLIC_JWT_SIGNING_KEY']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} flagged`)
  }
})

test('a secret on its own line is caught even next to a regex-literal line (common case)', () => {
  // Regex literals aren't fully parsed (documented), but the real-world layout —
  // secret on its own line — must never be missed. This locks that boundary.
  const src = 'const re = /https:\\/\\//\nconst k = process.env.NEXT_PUBLIC_STRIPE_SECRET'
  assert.equal(scanSecrets(src, 'a.ts').length, 1)
})

test('a hard secret is flagged even on a vendor whose public keys are allow-listed', () => {
  // FIREBASE_API_KEY is public by design (skip), but FIREBASE_PRIVATE_KEY is a real leak.
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FIREBASE_API_KEY', 'a.ts').length, 0)
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FIREBASE_PRIVATE_KEY', 'a.ts').length, 1)
})

test('known-public keys/tokens are NOT flagged even with the wider trigger', () => {
  for (const name of [
    'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_MAPBOX_TOKEN',
    'NEXT_PUBLIC_TURNSTILE_SITE_KEY', 'NEXT_PUBLIC_FIREBASE_API_KEY', 'NEXT_PUBLIC_GOOGLE_MAPS_API_KEY',
    'NEXT_PUBLIC_PUSHER_KEY', 'NEXT_PUBLIC_FIREBASE_VAPID_KEY',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 0, `expected ${name} NOT flagged`)
  }
})

// ---- Pages Router ----
test('isPagesApiFile / pagesRouteUrl handle pages/api', () => {
  assert.equal(isPagesApiFile('pages/api/charge.ts'), true)
  assert.equal(isPagesApiFile('src/pages/api/user/index.ts'), true)
  assert.equal(isPagesApiFile('pages/_app.tsx'), false)
  assert.equal(isPagesApiFile('app/api/x/route.ts'), false)
  assert.equal(pagesRouteUrl('pages/api/charge.ts'), '/api/charge')
  assert.equal(pagesRouteUrl('src/pages/api/user/index.ts'), '/api/user')
})

test('a pages/api mutating handler with no auth is a warn', () => {
  const src = 'export default function handler(req, res){ if (req.method === "POST") { save(req.body) } }'
  const f = scanPagesRoute(src, 'pages/api/charge.ts')
  assert.equal(f.filter((x) => x.rule === 'unauth_mutation').length, 1)
})

test('a pages/api handler WITH auth is clean', () => {
  const src = 'export default async function handler(req, res){ const { data: { user } } = await supabase.auth.getUser(); if (req.method === "POST") save() }'
  assert.equal(scanPagesRoute(src, 'pages/api/charge.ts').length, 0)
})

test('a GET-only pages/api handler is not flagged', () => {
  const src = 'export default function handler(req, res){ if (req.method === "GET") res.json({}) }'
  assert.equal(scanPagesRoute(src, 'pages/api/list.ts').length, 0)
})

test('a pages/api webhook without signature verify is a warn', () => {
  const src = 'export default function handler(req, res){ const e = req.body; fulfill(e) }'
  const f = scanPagesRoute(src, 'pages/api/webhooks/stripe.ts')
  assert.equal(f.filter((x) => x.rule === 'unverified_webhook').length, 1)
})

test('a // inside a string does NOT swallow a secret on the same line (no false negative)', () => {
  const f = scanSecrets('const u = "//cdn.example"; const k = process.env.NEXT_PUBLIC_STRIPE_SECRET', 'a.ts')
  assert.equal(f.length, 1)
  assert.equal(f[0].object, 'NEXT_PUBLIC_STRIPE_SECRET')
})

test('a secret named only inside a real comment is not flagged', () => {
  const f = scanSecrets('// rotate NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY next week', 'a.ts')
  assert.equal(f.length, 0)
})

// ---- scanRoute ----
test('mutating route without auth is a warn', () => {
  const f = scanRoute('export async function POST(req){ await save() }', 'app/api/x/route.ts')
  assert.equal(f.filter((x) => x.rule === 'unauth_mutation').length, 1)
})

test('mutating route WITH auth is clean', () => {
  const f = scanRoute('export async function POST(){ const {data}=await supabase.auth.getUser() }', 'app/api/x/route.ts')
  assert.equal(f.length, 0)
})

test('getUserAgent / getUserId do NOT count as auth (no false negative)', () => {
  assert.equal(scanRoute('export async function POST(req){ const ua = getUserAgent(req); await save() }', 'app/api/x/route.ts').length, 1)
  assert.equal(scanRoute('export async function DELETE(req){ const id = getUserId(req.query); await del(id) }', 'app/api/x/route.ts').length, 1)
})

test('a real getUser() / .auth call still counts as auth (no false positive)', () => {
  assert.equal(scanRoute('export async function POST(){ const { data } = await supabase.auth.getUser() }', 'app/api/x/route.ts').length, 0)
})

test('a route using a centralized auth helper is clean (heuristic, no false alarm)', () => {
  const src = 'import { resolverAcessoEscrita } from "@/lib/auth"; export async function POST(){ const a = await resolverAcessoEscrita(supabase); if(!a.ok) return a.erro }'
  assert.equal(scanRoute(src, 'app/api/orcamentos/route.ts').length, 0)
})

test('a custom helper declared via authFns clears the route', () => {
  const src = 'export async function POST(){ await meuPortao(req) }'
  assert.equal(scanRoute(src, 'app/api/x/route.ts').length, 1) // unknown helper → still warns
  assert.equal(scanRoute(src, 'app/api/x/route.ts', { authFns: ['meuPortao'] }).length, 0)
})

test('a route that only MENTIONS a webhook url is not treated as a webhook', () => {
  const src = 'export async function POST(){ /* notification_url: /api/mp/webhook */ await resolverAcesso() }'
  const f = scanRoute(src, 'app/api/mercadopago/checkout/route.ts')
  assert.equal(f.filter((x) => x.rule === 'unverified_webhook').length, 0)
})

test('a GET-only route is not a mutation', () => {
  const f = scanRoute('export async function GET(){ return 1 }', 'app/api/x/route.ts')
  assert.equal(f.length, 0)
})

test('webhook route without signature verify is a warn (not unauth_mutation)', () => {
  const f = scanRoute('export async function POST(req){ const e=await req.json() }', 'app/api/webhooks/paddle/route.ts')
  assert.equal(f.length, 1)
  assert.equal(f[0].rule, 'unverified_webhook')
})

test('webhook route WITH signature verify is clean', () => {
  const f = scanRoute('export async function POST(req){ const s=req.headers.get("stripe-signature"); stripe.webhooks.constructEvent(b,s,secret) }', 'app/api/webhooks/stripe/route.ts')
  assert.equal(f.length, 0)
})

// ---- helpers ----
test('isRouteFile matches App Router route files', () => {
  assert.equal(isRouteFile('app/api/x/route.ts'), true)
  assert.equal(isRouteFile('src/app/api/x/route.tsx'), true)
  assert.equal(isRouteFile('app/lib/util.ts'), false)
})

test('routeUrl strips the app prefix and route groups', () => {
  assert.equal(routeUrl('app/api/webhooks/paddle/route.ts'), '/api/webhooks/paddle')
  assert.equal(routeUrl('src/app/(auth)/api/me/route.ts'), '/api/me')
})

// ---- integration over the fixture project ----
test('scan(fixtures) finds the leak and the two warnings', async () => {
  const r = await scan({ dir: fxDir })
  assert.equal(r.passed, false)
  assert.equal(r.problems, 1) // the NEXT_PUBLIC service role key
  const rules = r.findings.map((f) => f.rule)
  assert.ok(rules.includes('public_secret'))
  assert.ok(rules.includes('unauth_mutation'))
  assert.ok(rules.includes('unverified_webhook'))
  // the good routes produce nothing
  assert.ok(!r.findings.some((f) => (f.object || '').includes('/api/orders')))
  assert.ok(!r.findings.some((f) => (f.object || '').includes('/api/webhooks/stripe')))
})

test('report: secret is critical and the fix drops NEXT_PUBLIC_ + rotates', () => {
  assert.equal(levelOf('public_secret'), 'critical')
  const fix = fixFor({ rule: 'public_secret', object: 'NEXT_PUBLIC_STRIPE_SECRET' })
  assert.match(fix, /process\.env\.STRIPE_SECRET/)
  assert.match(fix, /ROTATE/)
})

test('report: markdown export carries severity and the fixes', async () => {
  const md = toMarkdown(enrich(await scan({ dir: fxDir })))
  assert.match(md, /# Auth Route Guard report/)
  assert.match(md, /🔴 CRITICAL/)
  assert.match(md, /\*\*Fix:\*\*/)
  assert.match(md, /```ts/)
})

test('allow-list silences a route by path and passes on secrets', async () => {
  const r = await scan({ dir: fxDir, allow: ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', '/api/charge', '/api/webhooks/paddle'] })
  assert.equal(r.passed, true)
  assert.equal(r.findings.length, 0)
  assert.ok(r.allowed.length >= 3)
})

// ---- P1 fix #2: public client tokens/keys must not cry wolf ----
test('#2 NEXT_PUBLIC_PADDLE_CLIENT_TOKEN is public by design — NOT flagged', () => {
  assert.equal(scanSecrets('const t = process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN', 'a.ts').length, 0)
})

test('#2 common public client-SDK tokens/keys are NOT flagged', () => {
  for (const name of [
    'NEXT_PUBLIC_PADDLE_CLIENT_TOKEN', 'NEXT_PUBLIC_STREAM_API_KEY', 'NEXT_PUBLIC_ALGOLIA_API_KEY',
    'NEXT_PUBLIC_LIVEKIT_URL', 'NEXT_PUBLIC_SENTRY_DSN', 'NEXT_PUBLIC_SEGMENT_WRITE_KEY',
    'NEXT_PUBLIC_LIVEBLOCKS_PUBLIC_KEY',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 0, `expected ${name} NOT flagged`)
  }
})

test('#2 a real CLIENT_SECRET is still flagged (HARD_SECRET wins over CLIENT_TOKEN exemption)', () => {
  assert.equal(scanSecrets('x = NEXT_PUBLIC_PADDLE_CLIENT_SECRET', 'a.ts').length, 1)
})

// P3 re-audit: an ADMIN key/token on a "public" vendor is still a real leak.
test('#admin ADMIN keys/tokens are flagged even on an otherwise-public vendor', () => {
  for (const name of [
    'NEXT_PUBLIC_ALGOLIA_ADMIN_KEY', 'NEXT_PUBLIC_FIREBASE_ADMIN_TOKEN',
    'NEXT_PUBLIC_ADMIN_KEY', 'NEXT_PUBLIC_SUPABASE_ADMIN_TOKEN',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} FLAGGED (admin credential)`)
  }
})

test('#admin a non-secret ADMIN_*/SERVER_* name is NOT flagged (no false positive)', () => {
  for (const name of ['NEXT_PUBLIC_ADMIN_URL', 'NEXT_PUBLIC_ADMIN_EMAIL', 'NEXT_PUBLIC_ADMIN_PATH', 'NEXT_PUBLIC_SERVER_URL']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 0, `expected ${name} NOT flagged`)
  }
  // the public search key stays exempt
  assert.equal(scanSecrets('x = NEXT_PUBLIC_ALGOLIA_API_KEY', 'a.ts').length, 0)
})

test('#server a SERVER_KEY/SERVER_TOKEN (e.g. FCM) is a hard secret; a public WRITE key is not', () => {
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FCM_SERVER_KEY', 'a.ts').length, 1)
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FIREBASE_SERVER_TOKEN', 'a.ts').length, 1)
  // WRITE is NOT barred — public analytics write keys are public by design
  assert.equal(scanSecrets('x = NEXT_PUBLIC_SEGMENT_WRITE_KEY', 'a.ts').length, 0)
})

// REGRESSION (0.1.3 broke this): ADMIN_KEY / SERVER_TOKEN must match the WHOLE
// word, not a substring of legit public config → no false positive on installs.
test('#anchor ADMIN_KEY/SERVER_TOKEN as a substring of a public name is NOT flagged', () => {
  for (const name of [
    'NEXT_PUBLIC_ADMIN_KEYCLOAK_URL', 'NEXT_PUBLIC_SERVER_TOKENIZER_URL',
    'NEXT_PUBLIC_ADMIN_KEYBOARD_LAYOUT', 'NEXT_PUBLIC_SERVER_KEYSPACE',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 0, `expected ${name} NOT flagged (public config, not a key)`)
  }
  // but the real whole-word key still flags
  assert.equal(scanSecrets('x = NEXT_PUBLIC_ALGOLIA_ADMIN_KEY', 'a.ts').length, 1)
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FCM_SERVER_TOKEN', 'a.ts').length, 1)
})

// GLUED (re-audit → 6.5→): an ALL-CAPS name with NO separator (SECRETKEY,
// SERVICEROLEKEY) survived normalization and matched no snake pattern. The fix
// canonicalizes the CLASS of spelling: camelCase, snake, kebab and glued all fold
// to one separator-free form, so a secret in ANY spelling is caught, once.
test('#glued all-caps glued secrets (no separator) are caught — bypass closed', () => {
  for (const name of [
    'NEXT_PUBLIC_SECRETKEY', 'NEXT_PUBLIC_PRIVATEKEY', 'NEXT_PUBLIC_SERVICEROLEKEY',
    'NEXT_PUBLIC_MASTERKEY', 'NEXT_PUBLIC_ADMINKEY', 'NEXT_PUBLIC_SERVERTOKEN', 'NEXT_PUBLIC_APIKEY',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} FLAGGED (glued)`)
  }
})

test('#glued the same secret in every spelling folds to one verdict (class, not instance)', () => {
  for (const name of ['NEXT_PUBLIC_serviceRoleKey', 'NEXT_PUBLIC_service_role_key', 'NEXT_PUBLIC_SERVICE_ROLE_KEY', 'NEXT_PUBLIC_SERVICEROLEKEY', 'NEXT_PUBLIC_ServiceRoleKey']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} FLAGGED`)
  }
  // and a public one folds the same way — still exempt in every spelling
  for (const name of ['NEXT_PUBLIC_supabaseAnonKey', 'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_supabaseanonkey']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 0, `expected ${name} NOT flagged`)
  }
})

// BYPASS (re-audit → 8.5): a kebab-case suffix (service-role-key) was truncated at
// the first hyphen by the extraction regex before canonicalSuffix ever saw it, so
// the secret leaked. The extraction class now includes `-`.
test('#kebab a kebab-case NEXT_PUBLIC_ secret is caught, public kebab names stay exempt', () => {
  for (const name of ['NEXT_PUBLIC_service-role-key', 'NEXT_PUBLIC_stripe-secret-key', 'NEXT_PUBLIC_private-key'])
    assert.equal(scanSecrets(`x = process.env['${name}']`, 'a.ts').length, 1, `expected ${name} FLAGGED (kebab)`)
  for (const name of ['NEXT_PUBLIC_api-key-name', 'NEXT_PUBLIC_public-key', 'NEXT_PUBLIC_publishable-key', 'NEXT_PUBLIC_segment-write-key'])
    assert.equal(scanSecrets(`x = process.env['${name}']`, 'a.ts').length, 0, `expected ${name} NOT flagged`)
})

test('#case a mixed/lower-case NEXT_PUBLIC_ secret name is still caught (case bypass closed)', () => {
  assert.equal(scanSecrets('x = NEXT_PUBLIC_stripe_secret', 'a.ts').length, 1)
  assert.equal(scanSecrets('x = NEXT_PUBLIC_Supabase_Service_Role_Key', 'a.ts').length, 1)
  // still no false positive on a public one, any case
  assert.equal(scanSecrets('x = NEXT_PUBLIC_supabase_anon_key', 'a.ts').length, 0)
})

// BYPASS (re-audit → 7.5): a camelCase suffix with NO separators (serviceRoleKey)
// used to survive .toUpperCase() as SERVICEROLEKEY — matched no snake_case pattern
// → a real secret leaked past the gate. normalizeSuffix now camel-splits first.
test('#camel a camelCase NEXT_PUBLIC_ secret (no separators) is caught — bypass closed', () => {
  for (const name of ['NEXT_PUBLIC_serviceRoleKey', 'NEXT_PUBLIC_ServiceRoleKey', 'NEXT_PUBLIC_SERVICE_ROLE_KEY']) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} FLAGGED (camelCase bypass)`)
  }
  // camelCase public config stays exempt after camel-split (supabaseAnonKey → ANON_KEY)
  assert.equal(scanSecrets('x = NEXT_PUBLIC_supabaseAnonKey', 'a.ts').length, 0)
})

// New known-secret patterns: MASTER_KEY (root cred, beats PUBLIC_OK), DATABASE_URL
// (a bare Postgres URL embeds the password), and APIKEY with no separator.
test('#patterns MASTER_KEY / DATABASE_URL / APIKEY are flagged (screaming + camelCase)', () => {
  for (const name of [
    'NEXT_PUBLIC_MASTER_KEY', 'NEXT_PUBLIC_masterKey', 'NEXT_PUBLIC_ALGOLIA_MASTER_KEY',
    'NEXT_PUBLIC_DATABASE_URL', 'NEXT_PUBLIC_databaseUrl',
    'NEXT_PUBLIC_APIKEY', 'NEXT_PUBLIC_apiKey',
  ]) {
    assert.equal(scanSecrets(`x = ${name}`, 'a.ts').length, 1, `expected ${name} FLAGGED`)
  }
})

test('#patterns a genuinely public DATABASE_URL (Firebase) stays exempt, and no over-match', () => {
  // Firebase's Realtime DB URL is public by design → PUBLIC_OK still waves it through.
  assert.equal(scanSecrets('x = NEXT_PUBLIC_FIREBASE_DATABASE_URL', 'a.ts').length, 0)
  // APIKEY (no separator) must not swallow the public STREAM_API_KEY (has a separator).
  assert.equal(scanSecrets('x = NEXT_PUBLIC_STREAM_API_KEY', 'a.ts').length, 0)
})

// ---- P1 fix #3: allow-list must not silence via loose substring ----
test('#3 --allow key does NOT silence a real secret (fails need an exact name)', async () => {
  const r = await scan({ dir: fxDir, allow: ['key'] })
  assert.equal(r.passed, false)
  assert.ok(r.findings.some((f) => f.rule === 'public_secret'), 'the service-role secret must still fail')
})

test('#3 an exact secret name still silences it', async () => {
  const r = await scan({ dir: fxDir, allow: ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY'] })
  assert.ok(!r.findings.some((f) => f.rule === 'public_secret'))
  assert.ok(r.allowed.some((f) => f.rule === 'public_secret'))
})

test('#3 rule:public_secret silences the whole class deliberately', async () => {
  const r = await scan({ dir: fxDir, allow: ['rule:public_secret'] })
  assert.ok(!r.findings.some((f) => f.rule === 'public_secret'))
})

// ---- P1 fix #1: ReDoS bound + file-size cap ----
test('#1 the auth regex is bounded — a huge word-char run scans fast (ReDoS guard)', () => {
  const big = 'export async function POST(){}\n' + 'const x = require' + 'a'.repeat(200_000)
  const start = Date.now()
  const f = scanRoute(big, 'app/api/x/route.ts')
  const ms = Date.now() - start
  assert.ok(ms < 1000, `auth scan took ${ms}ms — expected < 1000ms (ReDoS guard)`)
  assert.equal(f.filter((x) => x.rule === 'unauth_mutation').length, 1) // still correctly flagged
})

test('#1 an oversized file is skipped and reported (no silent cap, no scan)', async () => {
  const d = await mkdtemp(join(tmpdir(), 'authguard-'))
  try {
    const big = join(d, 'route.ts')
    // >1MB AND it contains a would-be secret — proving it's skipped, not just clean
    await writeFile(big, 'const k = process.env.NEXT_PUBLIC_STRIPE_SECRET;\n' + '// filler\n'.repeat(150_000))
    const r = await scan({ files: [big] })
    assert.equal(r.findings.length, 0)
    assert.equal(r.skipped.length, 1)
  } finally {
    await rm(d, { recursive: true, force: true })
  }
})

// NEW COVERAGE (was declared "not covered yet"): a Server Action ('use server') is
// a client-callable mutation entry point. A DB write with no auth check is flagged.
test('#serveraction a use-server write with no auth is flagged; auth/read-only/non-action stay silent', () => {
  const flag = (src) => scanServerAction(src, 'a.ts').length
  // writes with no auth → flagged
  assert.equal(flag(`'use server'\nexport async function add(fd){ await db.from('notes').insert({x:1}) }`), 1)
  assert.equal(flag(`"use server"\nexport async function del(id){ await sb.from('t').delete().eq('id',id) }`), 1)
  assert.equal(flag('\'use server\'\nexport async function upd(){ await sql`update t set x=1 where id=2` }'), 1)
  assert.equal(flag(`'use server'\nexport async function u(){ await prisma.user.delete({ where:{ id } }) }`), 1, 'prisma write')
  // no false positives — the write must be a REAL db write, not a same-named method
  assert.equal(flag(`'use server'\nexport async function add(){ const u = await getUser(); await db.from('n').insert({x:1}) }`), 0, 'auth present')
  assert.equal(flag(`'use server'\nexport async function add(){ const u = await requireUser(); await db.from('n').insert({}) }`), 0, 'auth helper present')
  assert.equal(flag(`'use server'\nexport async function list(){ return db.from('n').select('*') }`), 0, 'read-only action')
  assert.equal(flag(`export async function add(){ await db.from('n').insert({}) }`), 0, 'not a Server Action (no directive)')
  // the adoption-killer FPs: same-named method on cookies/formData/Map/etc is NOT a db write
  assert.equal(flag(`'use server'\nexport async function logout(){ cookies().delete('session') }`), 0, 'cookies().delete (logout)')
  assert.equal(flag(`'use server'\nexport async function f(fd){ fd.delete('x'); await noop() }`), 0, 'formData.delete')
  assert.equal(flag(`'use server'\nexport async function f(){ headers().delete('h'); myMap.delete(k) }`), 0, 'headers/Map .delete')
  assert.equal(flag(`const label = "use server"\nexport async function f(){ await db.from('t').insert({}) }`), 0, 'string literal, not a directive')
})
