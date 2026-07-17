import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { scanSecrets, scanRoute, scanPagesRoute, isRouteFile, isPagesApiFile, routeUrl, pagesRouteUrl } from '../src/rules.mjs'
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
