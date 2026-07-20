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
  // the write must be in the SAME chain as .from() — a read then an unrelated
  // cookie/formData .delete() must NOT bridge into a false alarm
  assert.equal(flag(`'use server'\nexport async function logout(){ await sb.from('u').select('name'); cookies().delete('sb') }`), 0, 'read + clear-cookie (no bridge)')
  assert.equal(flag(`'use server'\nexport async function f(fd){ await sb.from('u').select('id'); fd.delete('csrf') }`), 0, 'read + formData.delete (no bridge)')
  // knex idiom still caught
  assert.equal(flag(`'use server'\nexport async function del(id){ await knex('users').where({ id }).del() }`), 1, 'knex write')
  // raw SQL only counts when EXECUTED (tagged template / .query()), not English prose
  assert.equal(flag(`'use server'\nexport async function f(){ await sb.from('t').select('*'); return 'You can delete from your list' }`), 0, 'english "delete from" in a string')
  assert.equal(flag(`'use server'\nexport async function f(){ await sb.from('t').select('*'); throw new Error('Failed to delete from cache') }`), 0, 'english in an Error')
  assert.equal(flag('\'use server\'\nexport async function f(){ await sql`delete from t where id=1` }'), 1, 'sql`` tagged template')
  assert.equal(flag(`'use server'\nexport async function f(){ await db.query('delete from users where id=$1',[id]) }`), 1, 'db.query() raw')
})

// Server Actions are judged PER exported function now — an auth call in one action
// must not clear an unauthed write in another (the file-level false negative).
test('#serveraction-perfn a mixed file flags only the unauthed action', () => {
  const flag = (src) => scanServerAction(src, 'a.ts').length
  const mixed = `'use server'
export async function safe(){ const u = await getUser(); await db.from('n').insert({}) }
export async function danger(id){ await db.from('n').delete().eq('id', id) }`
  assert.equal(flag(mixed), 1, 'the unauthed action is caught even though a sibling authenticates')
  const both = `'use server'
export async function a(){ await db.from('n').insert({}) }
export async function b(id){ await db.from('n').delete().eq('id', id) }`
  assert.equal(flag(both), 2, 'two unauthed actions → two findings')
  // a shared auth helper whose name matches the auth heuristic still clears the action
  const helper = `'use server'
async function checkAuth(){ return getUser() }
export async function add(){ await checkAuth(); await db.from('n').insert({}) }`
  assert.equal(flag(helper), 0, 'a called auth helper clears the action')
})

// ---- Re-audit fixes (19/07): the exact cases the adversarial audit proved ----

test('AUDIT-FIX: a vendor browser key does NOT break the build (no false alarm)', () => {
  // These are public BY DESIGN in the vendor's own docs. Failing CI on them is
  // what gets the gate uninstalled on day one.
  for (const name of [
    'NEXT_PUBLIC_MIXPANEL_TOKEN',
    'NEXT_PUBLIC_CONTENTFUL_ACCESS_TOKEN',
    'NEXT_PUBLIC_AMPLITUDE_API_KEY',
    'NEXT_PUBLIC_BUGSNAG_API_KEY',
    'NEXT_PUBLIC_UNSPLASH_ACCESS_KEY',
    'NEXT_PUBLIC_GIPHY_API_KEY',
    'NEXT_PUBLIC_TINYMCE_API_KEY',
    'NEXT_PUBLIC_CLARITY_TOKEN',
  ]) {
    const f = scanSecrets(`const k = process.env.${name}`, 'a.ts')
    assert.ok(!f.some((x) => x.severity === 'fail'), `${name} must not FAIL the build`)
  }
})

test('AUDIT-FIX: an unambiguous secret still FAILS', () => {
  for (const name of [
    'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
    'NEXT_PUBLIC_STRIPE_SECRET_KEY',
    'NEXT_PUBLIC_FIREBASE_PRIVATE_KEY',
    'NEXT_PUBLIC_ALGOLIA_ADMIN_KEY',
  ]) {
    const f = scanSecrets(`const k = process.env.${name}`, 'a.ts')
    assert.ok(f.some((x) => x.severity === 'fail'), `${name} must FAIL the build`)
  }
})

// OWNER DECISION (audit 20/07, round 4): the fail vs warn line is drawn by
// whether the NOUN can EVER be legitimately public, NOT by a vendor allow-list.
// A round-3 attempt made every non-exempt secret-shaped name FAIL, which broke
// CI for Alchemy/Infura/Weglot — real vendors that ship a public browser
// `*_API_KEY`. This splits the two:
//   - a noun that is never public (connection string, postgres url, LLM key,
//     *_SK, *_PAT, *_SECRET) → fail;
//   - a noun that a vendor may ship public (a generic `*_API_KEY`, a bare
//     `DATABASE_URL`, a bare `ACCESS_KEY`) → warn, gate with `--fail-on warn`.
test('fail vs warn is drawn by whether the noun can ever be public', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }

  // Never public → fail.
  for (const v of [
    'NEXT_PUBLIC_POSTGRES_URL', 'NEXT_PUBLIC_CONNECTION_STRING', 'NEXT_PUBLIC_MONGODB_URI',
    'NEXT_PUBLIC_REDIS_URL', 'NEXT_PUBLIC_ANTHROPIC_KEY', 'NEXT_PUBLIC_OPENAI_KEY',
    'NEXT_PUBLIC_GITHUB_PAT', 'NEXT_PUBLIC_STRIPE_SECRET_KEY', 'NEXT_PUBLIC_AWS_SECRET_ACCESS_KEY',
  ]) assert.equal(sev(v), 'fail', `${v} is never legitimately public — must fail`)

  // May be a vendor's public browser value → warn, not a build break. This is
  // what stops the gate breaking CI for Alchemy/Infura/Weglot on day one.
  for (const v of [
    'NEXT_PUBLIC_ALCHEMY_API_KEY', 'NEXT_PUBLIC_INFURA_API_KEY', 'NEXT_PUBLIC_WEGLOT_API_KEY',
    'NEXT_PUBLIC_WIDGETCO_API_KEY', 'NEXT_PUBLIC_DATABASE_URL', 'NEXT_PUBLIC_SOME_TOKEN',
  ]) assert.equal(sev(v), 'warn', `${v} may be a public vendor key — warn, don't break the build`)

  // Known-public vendor keys stay fully exempt — not even a warning.
  for (const v of [
    'NEXT_PUBLIC_MIXPANEL_TOKEN', 'NEXT_PUBLIC_PADDLE_CLIENT_TOKEN',
    'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_UNSPLASH_ACCESS_KEY',
    'NEXT_PUBLIC_FIREBASE_DATABASE_URL',
  ]) assert.equal(sev(v), 'clean', `${v} is public by design — stays clean`)
})

test('AUDIT-FIX: reading the signature header is NOT verifying it', () => {
  // The audit's probe: reads `paddle-signature`, then trusts the body anyway.
  const src = `export async function POST(req){ const signature = req.headers.get('paddle-signature'); const e = await req.json(); await fulfill(e); return Response.json({ok:true}) }`
  const f = scanRoute(src, 'app/api/webhooks/paddle/route.ts')
  assert.ok(f.some((x) => x.rule === 'unverified_webhook'), 'merely reading the header must still be flagged')
})

test('AUDIT-FIX: a real verification clears the webhook', () => {
  for (const body of [
    `const ok = crypto.createHmac('sha256', secret).update(raw).digest('hex')`,
    `const event = stripe.webhooks.constructEvent(raw, sig, secret)`,
    `const evt = wh.verify(payload, headers)`,
    `if (!timingSafeEqual(a, b)) return new Response('bad', {status:401})`,
  ]) {
    const src = `export async function POST(req){ ${body}; return Response.json({ok:true}) }`
    const f = scanRoute(src, 'app/api/webhooks/x/route.ts')
    assert.ok(!f.some((x) => x.rule === 'unverified_webhook'), `should be clean: ${body}`)
  }
})

test('AUDIT-FIX: an auth signal that only lives in a STRING does not clear a route', () => {
  const src = `export async function POST(req){ console.log("track user.auth event"); await db.insert(x); return Response.json({}) }`
  const f = scanRoute(src, 'app/api/notes/route.ts')
  assert.ok(f.some((x) => x.rule === 'unauth_mutation'), 'a string mention is not an auth check')
})

test('AUDIT-FIX: common auth helpers do not cry wolf', () => {
  for (const call of ['authorize(user, "write")', 'protectRoute(req)', 'restrictTo("admin")(req)', 'can(user, "edit")']) {
    const src = `export async function POST(req){ await ${call}; await db.insert(x); return Response.json({}) }`
    const f = scanRoute(src, 'app/api/notes/route.ts')
    assert.ok(!f.some((x) => x.rule === 'unauth_mutation'), `should be clean: ${call}`)
  }
})

test('AUDIT-FIX: a provider-qualified callback is a webhook; a bare OAuth callback is not', () => {
  const unverified = `export async function POST(req){ const e = await req.json(); await fulfill(e); return Response.json({}) }`
  const asWebhook = scanRoute(unverified, 'app/api/stripe/callback/route.ts')
  assert.ok(asWebhook.some((x) => x.rule === 'unverified_webhook'), '/api/stripe/callback IS a webhook')
  const oauth = scanRoute(unverified, 'app/auth/callback/route.ts')
  assert.ok(!oauth.some((x) => x.rule === 'unverified_webhook'), '/auth/callback is the OAuth leg, not a webhook')
})

// F4 (audit 20/07). An allow-list entry that silences NOTHING was accepted in
// silence. Stale suppression reads as protection-with-an-exception while the
// exception guards nothing — and when the finding returns under a slightly
// different name, the entry the author trusts will not cover it.
test('#allow an entry that matched nothing is reported, not swallowed', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ag-allow-'))
  try {
    const { mkdir } = await import('node:fs/promises')
    await mkdir(join(dir, 'app/api/charge'), { recursive: true })
    await writeFile(join(dir, 'lib.ts'), 'export const K = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n')
    await writeFile(join(dir, 'app/api/charge/route.ts'), 'export async function POST(req){ await db.from("t").insert({}) }\n')

    // A live entry silences and is NOT reported stale.
    const live = await scan({ dir, allow: ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY'] })
    assert.equal(live.problems, 0, 'the live entry really does silence')
    assert.deepEqual(live.staleAllows, [], 'a live entry is never called stale')

    // A dead entry is reported — the finding it claims to cover is still open.
    const dead = await scan({ dir, allow: ['NEXT_PUBLIC_RENAMED_LAST_MONTH', '/api/route-that-moved'] })
    assert.equal(dead.staleAllows.length, 2, 'both dead entries surface')
    assert.equal(dead.problems, 1, 'and the secret they failed to cover still fails the build')

    // Mixed: only the dead one is named.
    const mixed = await scan({ dir, allow: ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'rule:nonexistent_rule'] })
    assert.deepEqual(mixed.staleAllows, ['rule:nonexistent_rule'])
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// The `--allow` accumulation fix lived in bin/parseArgs with no test touching
// the binary at all, so any refactor of the parser reopened it in silence —
// and it was a silent-loss bug to begin with. Drive the real CLI.
test('#cli repeated --allow accumulates instead of discarding the first', async () => {
  const { spawnSync } = await import('node:child_process')
  const dir = await mkdtemp(join(tmpdir(), 'ag-cli-'))
  try {
    const { mkdir } = await import('node:fs/promises')
    await mkdir(join(dir, 'app/api/charge'), { recursive: true })
    await writeFile(join(dir, 'lib.ts'), 'export const K = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n')
    await writeFile(join(dir, 'app/api/charge/route.ts'), 'export async function POST(req){ await db.from("t").insert({}) }\n')

    const bin = fileURLToPath(new URL('../bin/auth-guard.mjs', import.meta.url))
    const run = (...args) => {
      const r = spawnSync(process.execPath, [bin, dir, ...args, '--json'], { encoding: 'utf8' })
      return JSON.parse(r.stdout)
    }

    // Two separate flags: BOTH must be honoured. Assigning meant the first was
    // dropped, so the secret it covered came back and failed the build while
    // the user believed it was allow-listed.
    const both = run('--allow', 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', '--allow', '/api/charge')
    assert.equal(both.allowed.length, 2, 'both --allow flags survive')
    assert.equal(both.findings.length, 0, 'and both findings are actually silenced')
    assert.deepEqual(both.staleAllows, [], 'neither entry is stale')

    // The comma-separated form documented in --help still works, and mixes.
    const mixed = run('--allow', 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY,/api/charge')
    assert.equal(mixed.allowed.length, 2, 'comma-separated still works')

    // --auth-fn had the identical assign-instead-of-push bug: a project with two
    // auth helpers lost the first, and every route it guards was flagged.
    await writeFile(join(dir, 'app/api/charge/route.ts'), 'export async function POST(req){ await meuPortao(req); await db.from("t").insert({}) }\n')
    const two = run('--auth-fn', 'guardaZingui', '--auth-fn', 'meuPortao')
    assert.ok(!two.findings.some((f) => f.rule === 'unauth_mutation'), 'the second --auth-fn must not erase the first')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// VERIFIER round 4 — two silent false-negatives, same root: an incomplete
// secret dictionary, not the tail mechanism (which held).
test('a named database/broker connection string always fails, whatever the engine', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  // `POSTGRES_URL` failed while these siblings — same class, credential in the
  // value, never public — read clean. All must fail now.
  for (const v of [
    'NEXT_PUBLIC_MYSQL_URL', 'NEXT_PUBLIC_MARIADB_URL', 'NEXT_PUBLIC_MSSQL_CONNECTION',
    'NEXT_PUBLIC_CLICKHOUSE_URL', 'NEXT_PUBLIC_COCKROACH_URL', 'NEXT_PUBLIC_PLANETSCALE_URL',
    'NEXT_PUBLIC_RABBITMQ_URL', 'NEXT_PUBLIC_AMQP_URL', 'NEXT_PUBLIC_KAFKA_URL',
    'NEXT_PUBLIC_POSTGRES_URL', 'NEXT_PUBLIC_MONGODB_URI',
    'NEXT_PUBLIC_REDIS_URL',
  ]) assert.equal(sev(v), 'fail', `${v} is a connection string with an embedded credential`)

  // A public URL is NOT a connection string: no engine token. These must stay
  // clean — breaking them is the false alarm a wide `*_URL` rule would cause.
  for (const v of [
    'NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_API_URL', 'NEXT_PUBLIC_SITE_URL',
    'NEXT_PUBLIC_APP_URL', 'NEXT_PUBLIC_BASE_URL', 'NEXT_PUBLIC_CDN_URL',
    'NEXT_PUBLIC_SENTRY_DSN', 'NEXT_PUBLIC_FIREBASE_DATABASE_URL',
  ]) assert.equal(sev(v), 'clean', `${v} is a public URL, not a connection string`)
})

test('an LLM-provider key fails in its canonical PROVIDER_API_KEY spelling too', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  // The name providers actually use has API in the middle. Both spellings must
  // fail — the README lists "LLM-provider key" under fail.
  for (const p of ['OPENAI', 'ANTHROPIC', 'GROQ', 'MISTRAL', 'COHERE', 'GEMINI', 'DEEPSEEK', 'XAI']) {
    assert.equal(sev(`NEXT_PUBLIC_${p}_API_KEY`), 'fail', `NEXT_PUBLIC_${p}_API_KEY must fail`)
    assert.equal(sev(`NEXT_PUBLIC_${p}_KEY`), 'fail', `NEXT_PUBLIC_${p}_KEY must fail`)
  }
  // …without dragging a generic vendor API key up with it — those still warn.
  assert.equal(sev('NEXT_PUBLIC_ALCHEMY_API_KEY'), 'warn')
  assert.equal(sev('NEXT_PUBLIC_WIDGETCO_API_KEY'), 'warn')
})

// VERIFIER round 5 — the connection-string axis ignored the pointer logic the
// rest of the scanner honors, so a PUBLIC link that merely NAMES an engine broke
// the build: a docs page, a status page, a logo image.
test('an engine-named public link is not a connection string', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  // Descriptor between the engine and the URL → a link ABOUT the engine → clean.
  for (const v of [
    'NEXT_PUBLIC_POSTGRES_DOCS_URL', 'NEXT_PUBLIC_REDIS_STATUS_URL',
    'NEXT_PUBLIC_MONGO_DASHBOARD_URL', 'NEXT_PUBLIC_KAFKA_CONSOLE_URL',
    'NEXT_PUBLIC_MYSQL_ADMIN_URL', 'NEXT_PUBLIC_POSTGRES_LOGO_URL',
    'NEXT_PUBLIC_ELASTICSEARCH_HEALTH_URL',
  ]) assert.equal(sev(v), 'clean', `${v} is a public link about the engine, not its DSN`)

  // …without letting a real connection string slip through on a benign middle
  // word: `POSTGRES_DATABASE_URL` is still the DSN.
  for (const v of [
    'NEXT_PUBLIC_POSTGRES_URL', 'NEXT_PUBLIC_MYSQL_URL',
    'NEXT_PUBLIC_POSTGRES_DATABASE_URL', 'NEXT_PUBLIC_REDIS_URL',
  ]) assert.equal(sev(v), 'fail', `${v} is a connection string`)
})

// VERIFIER round 5 (b-i) — the connection-string dictionary is curated, not
// exhaustive, but it must at least cover the product's OWN audience: Supabase's
// direct string, Prisma's DIRECT_URL, Vercel KV — all were silent.
test('connection-string coverage reaches the Supabase/Prisma/Vercel stack', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  for (const v of [
    'NEXT_PUBLIC_SUPABASE_DB_URL', 'NEXT_PUBLIC_DIRECT_URL', 'NEXT_PUBLIC_KV_URL',
    'NEXT_PUBLIC_DB_URL', 'NEXT_PUBLIC_ORACLE_URL', 'NEXT_PUBLIC_TURSO_URL',
    'NEXT_PUBLIC_LIBSQL_URL', 'NEXT_PUBLIC_SNOWFLAKE_URL',
  ]) assert.equal(sev(v), 'fail', `${v} embeds a credential — must fail`)

  // The alias tokens must not create false positives on their look-alikes.
  // REDIRECT_URL is not DIRECT_URL; a plain SUPABASE_URL is the public endpoint.
  for (const v of [
    'NEXT_PUBLIC_REDIRECT_URL', 'NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_API_URL',
    'NEXT_PUBLIC_SITE_URL', 'NEXT_PUBLIC_CDN_URL',
  ]) assert.equal(sev(v), 'clean', `${v} is a public URL`)

  // The smaller never-public names the audit named.
  for (const v of [
    'NEXT_PUBLIC_PGPASSWORD', 'NEXT_PUBLIC_STRIPE_RK',
    'NEXT_PUBLIC_STRIPE_RESTRICTED_KEY', 'NEXT_PUBLIC_GCP_SA_KEY',
  ]) assert.equal(sev(v), 'fail', `${v} is a real secret`)
})

// VERIFIER round 6 nits — a REST endpoint URL is not a connection string (its
// credential is a separate token), so failing it is a false alarm.
test('a REST endpoint URL is not a connection string', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  // The URL is public; the TOKEN beside it is the secret and is surfaced on its own.
  for (const v of ['NEXT_PUBLIC_KV_REST_API_URL', 'NEXT_PUBLIC_REDIS_REST_URL', 'NEXT_PUBLIC_UPSTASH_REDIS_REST_URL']) {
    assert.equal(sev(v), 'clean', `${v} is a REST endpoint, not a DSN`)
  }
  assert.equal(sev('NEXT_PUBLIC_KV_REST_API_TOKEN'), 'warn', 'the token is the real secret and is surfaced')
  // …and a genuine connection string (no REST) still fails.
  for (const v of ['NEXT_PUBLIC_KV_URL', 'NEXT_PUBLIC_REDIS_URL', 'NEXT_PUBLIC_DIRECT_URL']) {
    assert.equal(sev(v), 'fail', `${v} is a connection string`)
  }
})

// FULL-COVERAGE AUDIT (20/07) M1 — the fail-rule stopped at the FIRST secret
// word, so a leading softening word with a config tail silenced a bare hard
// secret later in the same name. `PASSWORD_RESET_SECRET` read clean.
test('a hard secret later in the name is not silenced by a leading softening word', () => {
  const sev = (v) => {
    const f = scanSecrets(`const k = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  // Every secret word is judged now, strongest verdict wins → these fail.
  for (const v of [
    'NEXT_PUBLIC_PASSWORD_RESET_SECRET', 'NEXT_PUBLIC_PASSWORD_POLICY_SECRET',
    'NEXT_PUBLIC_PRIVATE_URL_SECRET', 'NEXT_PUBLIC_PRIVATE_ENDPOINT_SECRET',
    'NEXT_PUBLIC_PASSWORD_HEADER_SECRET',
  ]) assert.equal(sev(v), 'fail', `${v} ends in a bare SECRET — must fail`)

  // …and the softening floor is intact: a name that is genuinely config still
  // clears. Judging every word must not turn these into false alarms.
  for (const v of [
    'NEXT_PUBLIC_PASSWORD_MIN_LENGTH', 'NEXT_PUBLIC_PRIVATE_BETA',
    'NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL', 'NEXT_PUBLIC_PASSWORD_RESET_URL',
    'NEXT_PUBLIC_DB_PASSWORD_FLAG', 'NEXT_PUBLIC_PRIVATE_BETA_FLAG',
  ]) assert.equal(sev(v), 'clean', `${v} is public config`)
})
