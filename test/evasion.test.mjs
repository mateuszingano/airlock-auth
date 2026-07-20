// EVASION SUITE — the probes from the 19/07 audit, made permanent.
//
// The existing fixtures were all canonical: `export async function POST`,
// `SERVICE_ROLE_KEY` with no suffix, one auth idiom. Sixty tests passed while
// thirteen real findings sat open, because the suite tested spellings the author
// had already thought of. These test the shapes an attacker — or a normal
// developer with a slightly different habit — actually writes.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanSecrets, scanRoute, scanPagesRoute, stripJsComments, isSourceFile, isRouteFile } from '../src/rules.mjs'

const ROUTE = 'app/api/x/route.ts'
const flaggedRoute = (src, opts) => scanRoute(src, ROUTE, opts).length > 0
const flaggedSecret = (name) => scanSecrets(`x = ${name}`, 'a.ts').length > 0
const INSERT = "await db.from('orders').insert(await req.json())"

// ── THE CRITICAL: any suffix after the secret word disarmed the only fail rule.
// `public_secret` is the one rule that can break a build, so this single gap made
// the whole product decorative for anyone who versions their env names.
test('#evasion a suffix after the secret word does not hide it', () => {
  for (const name of [
    'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_V2', 'NEXT_PUBLIC_STRIPE_SECRET_KEY_NEW',
    'NEXT_PUBLIC_DB_PASSWORD_PROD', 'NEXT_PUBLIC_API_KEY_2', 'NEXT_PUBLIC_SESSION_SIGNING_SECRET1',
    'NEXT_PUBLIC_PRIVATE_KEY_PEM', 'NEXT_PUBLIC_OPENAI_KEY_BACKUP', 'NEXT_PUBLIC_ADMIN_TOKEN_OLD',
    'NEXT_PUBLIC_ENCRYPTION_KEY_9', 'NEXT_PUBLIC_serviceRoleKeyV2',
  ]) assert.ok(flaggedSecret(name), `${name} must be flagged`)
})

test('#evasion public config is still not flagged (the anchor existed for a reason)', () => {
  for (const name of [
    'NEXT_PUBLIC_ADMIN_KEYCLOAK_URL', 'NEXT_PUBLIC_SERVER_TOKENIZER_URL',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_PADDLE_CLIENT_TOKEN',
    'NEXT_PUBLIC_ADMIN_URL', 'NEXT_PUBLIC_ADMIN_EMAIL', 'NEXT_PUBLIC_GA_MEASUREMENT_ID',
    'NEXT_PUBLIC_FIREBASE_API_KEY', 'NEXT_PUBLIC_api-key-name', 'NEXT_PUBLIC_SENTRY_DSN',
  ]) assert.ok(!flaggedSecret(name), `${name} must NOT be flagged`)
})

// ── The regex literal that swallowed the file, in both directions.
test('#evasion a regex literal does not swallow the rest of the file', () => {
  const naked = "const Q = /['\"]/g\nexport async function POST(req){ " + INSERT + ' }'
  assert.ok(flaggedRoute(naked), 'a naked handler after a regex literal must still be seen')

  const guarded =
    "const Q = /['\"]/g\nexport async function POST(req){ const { data: { user } } = await supabase.auth.getUser(); " +
    "if (!user) return new Response('no', { status: 401 }); await db.from('x').insert({}) }"
  assert.ok(!flaggedRoute(guarded), 'a guarded handler must not be flagged because its auth call was blanked')
})

test('#evasion division is not mistaken for a regex', () => {
  const out = stripJsComments('const rate = total / count / 2; const x = (a+b) / c;', { blankStrings: true })
  assert.match(out, /total \/ count/, 'division must survive intact')
})

test('#evasion template interpolation holds real code', () => {
  const out = stripJsComments('const u = `user:${await supabase.auth.getUser()}`;', { blankStrings: true })
  assert.match(out, /getUser/, 'code inside an interpolation is code, not string content')
})

test('#evasion an unterminated string is reported, not silently swallowed', () => {
  const state = {}
  const out = stripJsComments("const a = 'oops\nexport async function POST(){}", { blankStrings: true }, state)
  assert.equal(state.unterminated, 'string literal')
  assert.match(out, /POST/, 'the rest of the file must survive for the caller to judge')
})

// ── Export forms: sharing one handler across verbs is idiomatic, and was invisible.
test('#evasion every route-handler export form is seen', () => {
  for (const src of [
    `export async function POST(req){ ${INSERT} }`,
    `async function handler(req){ ${INSERT} }\nexport { handler as POST, handler as DELETE }`,
    'const handlers = {}; export const { POST } = handlers',
    `export const POST = async (req) => { ${INSERT} }`,
  ]) assert.ok(flaggedRoute(src), `unguarded handler must be seen in: ${src.slice(0, 44)}…`)
})

// ── Pages Router: the negative guard clause is THE way to write a POST-only route.
test('#evasion the Pages Router negative guard clause is understood', () => {
  const pages = (src) => scanPagesRoute(src, 'pages/api/h.ts').length > 0
  assert.ok(
    pages("export default async function h(req,res){ if (req.method !== 'POST') return res.status(405).end(); await db.insert(req.body) }"),
    'a !== POST guard means POST-only, which is mutating'
  )
  assert.ok(
    pages("export default async function h(req,res){ if (req.method.toUpperCase() !== 'DELETE') return res.status(405).end(); await db.del() }"),
    'the toUpperCase form counts too'
  )
  assert.ok(
    !pages("export default async function h(req,res){ if (req.method !== 'GET') return res.status(405).end(); res.json(await db.select()) }"),
    'a !== GET guard leaves a GET-only handler, which is not mutating'
  )
})

// ── Naming an auth helper is not calling it.
test('#evasion an auth helper imported but never called does not clear the route', () => {
  assert.ok(
    flaggedRoute(`import { requireUser } from '@/lib/auth'\nexport async function POST(req){ ${INSERT} }`),
    'an unused import must not count as an auth check'
  )
  assert.ok(
    flaggedRoute("export async function DELETE(req){ const checkUserAgent = req.headers.get('user-agent'); await db.from('x').delete() }"),
    'a variable merely NAMED like a helper is not a check'
  )
  assert.ok(
    !flaggedRoute("import { requireUser } from '@/lib/auth'\nexport async function POST(req){ await requireUser(req); await db.from('x').insert({}) }"),
    'an actual call still clears the route'
  )
})

test('#evasion a too-short --auth-fn token cannot silence the scanner', () => {
  const naked = `export async function POST(req){ ${INSERT} }`
  for (const fn of ['e', 'db', 'a']) assert.ok(flaggedRoute(naked, { authFns: [fn] }), `--auth-fn ${fn} must be refused`)
  assert.ok(
    !flaggedRoute("export async function POST(req){ await meuPortao(req); await db.from('x').insert({}) }", { authFns: ['meuPortao'] }),
    'a real helper name still works'
  )
})

// ── A webhook is verified by checking ITS signature, not by any .verify() call.
test('#evasion a generic .verify() does not clear a webhook', () => {
  const WH = 'app/api/webhooks/paddle/route.ts'
  const flagged = (src) => scanRoute(src, WH).length > 0
  assert.ok(
    flagged('export async function POST(req){ const b = await req.json(); schema.verify(b); await db.insert(b) }'),
    'payload validation is not signature verification'
  )
  assert.ok(
    flagged('export async function POST(req){ const t = jwt.verify(x); await db.insert(await req.json()) }'),
    'an unrelated jwt.verify is not it either'
  )
  assert.ok(
    !flagged("import { Webhook } from 'svix'; export async function POST(req){ const wh = new Webhook(s); wh.verify(body, headers); }"),
    'a real webhook signature check still clears it'
  )
})

// ── Files the walker could not see.
test('#evasion route files are recognized case-insensitively', () => {
  for (const p of ['app/api/x/route.ts', 'app/api/x/route.TS', 'app/api/x/route.Tsx'])
    assert.ok(isRouteFile(p) && isSourceFile(p), `${p} is a route Next.js serves`)
})

// ── Per-handler judgement: auth in ONE handler must not clear the others.
// `route.ts` files routinely export a guarded GET next to the POST someone
// forgot — and the whole-file test read that as covered.
test('#evasion auth in the GET does not clear a naked POST in the same file', () => {
  const GUARDED_GET = "export async function GET(){ const { data: { user } } = await supabase.auth.getUser(); return Response.json(user) }"
  const NAKED_POST = `export async function POST(req){ ${INSERT} }`
  const GUARDED_POST = "export async function POST(req){ const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('no', { status: 401 }); await db.from('o').insert({}) }"

  assert.ok(flaggedRoute(`${GUARDED_GET}\n${NAKED_POST}`), 'the naked POST must still be flagged')
  assert.ok(!flaggedRoute(`${GUARDED_GET}\n${GUARDED_POST}`), 'when both are guarded, nothing is flagged')
  assert.ok(flaggedRoute(`${NAKED_POST}\nexport async function DELETE(){ const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('no'); await db.from('o').delete() }`), 'a guarded DELETE does not cover a naked POST')
  // a shared/aliased body is judged file-wide, since the body really is shared
  assert.ok(!flaggedRoute("async function handler(req){ const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('no'); await db.from('o').insert({}) }\nexport { handler as POST }"), 'an aliased handler with a real check stays clean')
})

// ── the 19/07 re-audit: Critical + two Highs ──

import { scanServerAction } from '../src/rules.mjs'
import { levelOf } from '../src/report.mjs'
import { scan } from '../src/scan.mjs'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// CRITICAL. stripJsComments could always report an unterminated construct
// through its `state` out-param — and no caller ever passed one, so the
// detection was dead code while the README promised it worked. A stray `/*`
// blanks the rest of the file, so a SERVICE_ROLE_KEY below it vanished and the
// gate printed "No exposed secrets", exit 0.
test('#unterminated a file that ends inside an open comment FAILS, never reports clean', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ag-unterm-'))
  try {
    await writeFile(
      join(dir, 'leak.ts'),
      '/* oops never closed\nexport const K = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n',
    )
    const r = await scan({ dir })
    assert.equal(r.passed, false, 'a file we could not read must not pass')
    const f = r.findings.find((x) => x.rule === 'unparsable')
    assert.ok(f, 'and it is reported explicitly')
    assert.equal(f.severity, 'fail')
    assert.ok(r.skipped.some((s) => s.includes('leak.ts')), 'it also appears in skipped')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('#unterminated every unterminated construct is caught, not just comments', () => {
  for (const src of ['/* open', "const s = 'open", 'const t = `open', 'const u = `${ open']) {
    const st = {}
    stripJsComments(src, {}, st)
    assert.ok(st.unterminated, `${JSON.stringify(src)} must report unterminated`)
  }
  const ok = {}
  stripJsComments('/* closed */ const s = "fine"', {}, ok)
  assert.equal(ok.unterminated, null, 'and a well-formed file reports nothing')
})

// HIGH. A build broken over a number. `PASSWORD_MIN_LENGTH` has `MIN` after the
// secret word, which said nothing, so trivially public config became a CRITICAL
// telling the reader to ROTATE THE KEY.
test('#config public configuration knobs are not secrets', () => {
  const sev = (v) => {
    const f = scanSecrets(`export const x = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  for (const v of [
    'NEXT_PUBLIC_PASSWORD_MIN_LENGTH', 'NEXT_PUBLIC_PRIVATE_BETA',
    'NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL', 'NEXT_PUBLIC_SESSION_TIMEOUT_SECONDS',
    'NEXT_PUBLIC_PASSWORD_POLICY', 'NEXT_PUBLIC_API_KEY_HEADER',
  ]) assert.equal(sev(v), 'clean', `${v} is public config, not a secret`)

  // …and the versioned-suffix scar stays closed: these tails are NOT config.
  for (const v of [
    'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'NEXT_PUBLIC_SERVICE_ROLE_KEY_V2',
    'NEXT_PUBLIC_STRIPE_SECRET_KEY_NEW', 'NEXT_PUBLIC_DB_PASSWORD_PROD',
    'NEXT_PUBLIC_SERVICE_ROLE_KEY_BACKUP',
  ]) assert.equal(sev(v), 'fail', `${v} is a real secret and must break the build`)

  // the original non-regression pair
  assert.equal(sev('NEXT_PUBLIC_ADMIN_KEYCLOAK_URL'), 'clean')
  assert.equal(sev('NEXT_PUBLIC_SERVER_TOKENIZER_URL'), 'clean')
})

// HIGH. scanServerAction computed `code` (strings blanked) and never used it,
// so a string MENTIONING an auth helper cleared an action that deleted rows —
// caught in a route handler, missed in a Server Action.
test('#serveraction auth inside a string does not clear a write', () => {
  const mentioned = `'use server'
export async function deleteEverything(fd) {
  const msg = 'call requireUser() before mutating'
  await db.from('accounts').delete().eq('id', fd.get('id'))
}`
  assert.equal(scanServerAction(mentioned, 'a.ts').length, 1, 'a string is not a check')

  const real = `'use server'
export async function deleteThing(fd) {
  const user = await requireUser()
  await db.from('accounts').delete().eq('id', fd.get('id'))
}`
  assert.equal(scanServerAction(real, 'a.ts').length, 0, 'a real call still clears it')

  // and raw SQL — which lives INSIDE a string — must still count as a write
  assert.equal(
    scanServerAction("'use server'\nexport async function f(){ await db.query('delete from users where id=$1',[id]) }", 'a.ts').length,
    1,
    'blanking strings must not hide raw SQL writes',
  )
})

test('#label a fail is never printed below HIGH, a warn never above MEDIUM', () => {
  for (const rule of ['public_secret', 'unparsable', 'unauth_mutation', 'unauth_server_action', 'a_rule_added_later']) {
    assert.ok(['critical', 'high'].includes(levelOf(rule, 'fail')), `${rule} fail`)
    assert.ok(['medium', 'low'].includes(levelOf(rule, 'warn')), `${rule} warn`)
  }
})

// A measured class of false negatives: every comparison was exact, so a plural
// or the abbreviation people actually type walked straight past the gate.
test('#plural plurals and common abbreviations are the same secret', () => {
  const sev = (v) => {
    const f = scanSecrets(`export const x = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  for (const v of [
    'NEXT_PUBLIC_SMTP_PASS', 'NEXT_PUBLIC_DB_PASS', 'NEXT_PUBLIC_MONGODB_URI',
    'NEXT_PUBLIC_REDIS_URL', 'NEXT_PUBLIC_SECRETS', 'NEXT_PUBLIC_API_KEYS',
    'NEXT_PUBLIC_TOKENS', 'NEXT_PUBLIC_PASSWORDS', 'NEXT_PUBLIC_SVC_ROLE_KEY',
    'NEXT_PUBLIC_GITHUB_PAT', 'NEXT_PUBLIC_STRIPE_SK',
  ]) assert.notEqual(sev(v), 'clean', `${v} is a real secret and was being missed`)
})

test('#plural widening the matcher did not create new false alarms', () => {
  const sev = (v) => {
    const f = scanSecrets(`export const x = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  for (const v of [
    'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_API_URL',
    'NEXT_PUBLIC_SITE_URL', 'NEXT_PUBLIC_ADMIN_KEYCLOAK_URL', 'NEXT_PUBLIC_SERVER_TOKENIZER_URL',
    'NEXT_PUBLIC_PASSWORD_MIN_LENGTH', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    'NEXT_PUBLIC_PADDLE_CLIENT_TOKEN',
    // These six are the ones the first attempt at this fix broke. It required
    // EVERY tail segment to be a known-harmless word, so an unlisted word like
    // URL or TEXT forced a CRITICAL telling the reader to ROTATE a docs link.
    // An exhaustive list of harmless words does not exist, which is why the
    // rule asks whether the name POINTS AT a secret instead.
    'NEXT_PUBLIC_PASSWORD_RESET_URL',
    'NEXT_PUBLIC_PASSWORDS_POLICY_TEXT', 'NEXT_PUBLIC_TOKEN_MAX_AGE',
    'NEXT_PUBLIC_TOKENS_PER_PAGE', 'NEXT_PUBLIC_API_KEYS_HELP_LINK',
  ]) assert.equal(sev(v), 'clean', `${v} is public by design`)

  // `SECRETS_DOCS_URL` moved from clean to WARN when the default was inverted: a
  // bare `SECRET` word is too strong to be cleared by a pointer word alone, or
  // `REVALIDATE_SECRET_ENDPOINT` (a real Vercel/Next name) would stay silent
  // too. It is surfaced as a warning, not a build break — the safe direction.
  assert.equal(sev('NEXT_PUBLIC_SECRETS_DOCS_URL'), 'warn')
})

// The fix that liberated app/api/build removed depth-based skipping with it, so
// a nested app/api/node_modules/ was walked: third-party files scanned and
// findings reported against code the reader cannot fix.
test('#walk node_modules is skipped at any depth; app/api/build is not', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ag-walk-'))
  try {
    const { mkdir } = await import('node:fs/promises')
    await mkdir(join(dir, 'app/api/node_modules/evil'), { recursive: true })
    await mkdir(join(dir, 'app/api/build'), { recursive: true })
    await writeFile(join(dir, 'app/api/node_modules/evil/index.js'), 'export const K = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n')
    await writeFile(join(dir, 'app/api/build/route.ts'), 'export async function POST(req){ await db.from("t").delete().eq("id",1) }\n')
    const r = await scan({ dir })
    assert.ok(!r.findings.some((f) => String(f.file).includes('node_modules')), 'no findings from vendor code')
    assert.ok(r.findings.some((f) => String(f.file).includes('build')), 'app/api/build is still a route we check')
    assert.ok(r.skipped.some((s) => s.includes('node_modules')), 'and the skip is reported, never silent')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// A monorepo keeps its artifacts at apps/web/dist, not at the root. Skipping
// build output only at the root meant a stale bundle broke a clean build,
// pointing at generated code the developer cannot fix. Skipping it everywhere
// hid app/api/build/route.ts, where `build` is a URL segment. The rule is about
// what the name MEANS where it sits.
test('#walk build output is skipped at any depth, except inside a route tree', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ag-mono-'))
  try {
    const { mkdir } = await import('node:fs/promises')
    await mkdir(join(dir, 'apps/web/dist'), { recursive: true })
    await mkdir(join(dir, 'packages/ui/build'), { recursive: true })
    await mkdir(join(dir, 'apps/web/app/api/build'), { recursive: true })
    await writeFile(join(dir, 'apps/web/dist/bundle.js'), 'export const K = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n')
    await writeFile(join(dir, 'packages/ui/build/out.js'), 'export const K = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n')
    await writeFile(join(dir, 'apps/web/app/api/build/route.ts'), 'export async function POST(req){ await db.from("t").delete().eq("id",1) }\n')

    const r = await scan({ dir })
    assert.ok(!r.findings.some((f) => /dist|packages/.test(String(f.file))), 'generated bundles must not break a clean build')
    assert.ok(r.findings.some((f) => /api.build/.test(String(f.file))), 'app/api/build IS a route and stays checked')
    assert.ok(r.skipped.some((s) => s.includes('dist')), 'and the skip is reported, never silent')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT 20/07 — the two findings that held the release at 0,0.
// ─────────────────────────────────────────────────────────────────────────────

// CRITICAL. The tail-word amnesty was applied with `.some()` over the WHOLE
// tail, so ONE known-safe word ANYWHERE downstream cleared the name. That
// disarmed the single rule that can fail a build: a service_role key with a
// trailing `_MAX` shipped into the browser bundle reported CLEAN. The headline
// promise — "fails the build on a NEXT_PUBLIC_ secret" — was false for every
// name shaped this way.
test('#tail a trailing config word does not disarm a credential', () => {
  const sev = (v) => {
    const f = scanSecrets(`export const x = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }

  // Was `clean` for all of these. A credential PHRASE is never public config,
  // whatever trails it.
  for (const v of [
    'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_MAX', 'NEXT_PUBLIC_SERVICE_ROLE_KEY_MODE',
    'NEXT_PUBLIC_SERVICE_ROLE_KEY_COUNT', 'NEXT_PUBLIC_STRIPE_SECRET_KEY_RESET',
    'NEXT_PUBLIC_FIREBASE_PRIVATE_KEY_TYPE', 'NEXT_PUBLIC_DB_PASSWORD_PROD',
  ]) assert.equal(sev(v), 'fail', `${v} is a shipped credential and must break the build`)

  // KNOWN LIMIT, asserted so it stays a decision and not a drift: a bare secret
  // WORD followed by a config word is read as config, because that is what it
  // is in English far more often than not (`PRIVATE_BETA`, `PASSWORD_MIN_…`).
  // `DB_PASSWORD_FLAG` pays for that: it reads clean. Naming a credential after
  // a config word is the one spelling this rule cannot see, and it is listed in
  // the README's coverage gaps rather than left for a user to discover.
  assert.equal(sev('NEXT_PUBLIC_DB_PASSWORD_FLAG'), 'clean')
  assert.equal(sev('NEXT_PUBLIC_DB_PASSWORD'), 'fail', 'the same name without the config word still fails')

  // Ambiguous — a pointer word further down the tail. Reported, not silenced,
  // and not a build break either: we cannot prove it holds the credential and
  // we refuse to prove it does not.
  assert.equal(sev('NEXT_PUBLIC_SERVICE_ROLE_KEY_PROD_URL'), 'warn')

  // …and the false alarms this amnesty existed to prevent stay prevented. A
  // bare secret WORD is ordinary English that modifies the noun after it.
  for (const v of [
    'NEXT_PUBLIC_PASSWORD_MIN_LENGTH', 'NEXT_PUBLIC_PRIVATE_BETA',
    'NEXT_PUBLIC_PASSWORD_RESET_URL', 'NEXT_PUBLIC_API_KEY_HEADER',
    'NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL', 'NEXT_PUBLIC_ADMIN_KEYCLOAK_URL',
    'NEXT_PUBLIC_SERVER_TOKENIZER_URL', 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  ]) assert.equal(sev(v), 'clean', `${v} is public config, not a secret`)
})

// HIGH. A Pages Router default export answers EVERY verb. Requiring a
// RECOGNIZED method-check before flagging meant "I could not read how this
// route dispatches" rendered as "this route does not mutate" — so a handler
// that never looks at req.method and then deletes rows read clean.
test('#pages a write with no method-check at all is a mutation', () => {
  const rule = (src) => {
    const f = scanPagesRoute(src, 'pages/api/x.ts')
    return f[0] ? f[0].rule : 'clean'
  }

  assert.equal(
    rule(`export default async function h(req,res){ await supabase.from('users').delete().eq('id',req.body.id); res.json({ok:1}) }`),
    'unauth_mutation',
    'answers POST, writes, never checks the verb or the caller'
  )

  // …without inventing a false alarm on the shapes that are genuinely fine.
  assert.equal(
    rule(`export default async function h(req,res){ const {data:{user}}=await supabase.auth.getUser(); await supabase.from('users').delete().eq('id',1) }`),
    'clean', 'it authenticates'
  )
  assert.equal(
    rule(`export default async function h(req,res){ const {data}=await supabase.from('users').select(); res.json(data) }`),
    'clean', 'read-only'
  )
  assert.equal(
    rule(`export default async function h(req,res){ if(req.method!=='GET') return res.status(405).end(); await supabase.from('l').insert({}) }`),
    'clean', 'GET-only by a recognized guard'
  )
  // A method-check we cannot parse is a COVERAGE GAP, not a licence to guess.
  assert.equal(
    rule(`export default async function h(req,res){ const m=req.method; if(!['POST'].includes(m)) return res.end(); await supabase.from('u').insert({}) }`),
    'clean', 'it does consult req.method — unparsed shape stays silent, by design'
  )
})

// VERIFIER PASS (20/07). The first fix narrowed the tail amnesty from "any
// position" to "position 1" and stopped there, which left the SAME exploit open
// under a different suffix: `SERVICE_ROLE_KEY_ROTATION` stayed clean because
// ROTATION is a pointer word, not a config word. And the credential names most
// common in a Next.js app (JWT_SECRET, WEBHOOK_SECRET, ENCRYPTION_KEY…) were
// never phrases at all, so every one of them was softened by any trailing word.
test('#tail credential PHRASES survive every trailing word', () => {
  const sev = (v) => {
    const f = scanSecrets(`export const x = process.env.${v}`, 'a.ts')
    return f[0] ? f[0].severity : 'clean'
  }
  const stems = [
    'SUPABASE_SERVICE_ROLE_KEY', 'ENCRYPTION_KEY', 'SIGNING_KEY', 'WEBHOOK_SECRET',
    'STRIPE_WEBHOOK_SIGNING_SECRET', 'SESSION_SECRET', 'JWT_SECRET', 'CLIENT_SECRET',
    'NEXTAUTH_SECRET', 'SECRET_KEY', 'PRIVATE_KEY', 'MASTER_KEY', 'ADMIN_KEY',
  ]
  // NO config word softens a phrase: all of them stay a build break. ROTATION,
  // REFRESH, REQUIRED, LIMIT and PER are config words (a key's rotation setting
  // is still about the key), not pointers — leaving them on the pointer list is
  // what let `SERVICE_ROLE_KEY_ROTATION` read clean for two rounds.
  for (const s of stems) {
    for (const suf of ['MODE', 'TYPE', 'PREFIX', 'MAX', 'MIN', 'COUNT', 'BETA', 'FLAG', 'RESET', 'ROTATION', 'REFRESH', 'REQUIRED', 'LIMIT', 'PER']) {
      assert.equal(sev(`NEXT_PUBLIC_${s}_${suf}`), 'fail', `NEXT_PUBLIC_${s}_${suf} is a shipped credential`)
    }
    // A TRUE pointer word (URL, DOCS, HEADER…) genuinely points outward, so it
    // must never BREAK THE BUILD. But every stem here is a HARD credential with
    // NO legitimately public form, so a pointer after it is ambiguous, not proof
    // it points away: it WARNS, never clean and never fail.
    for (const suf of ['DOCS_URL', 'HEADER', 'ENDPOINT']) {
      assert.equal(sev(`NEXT_PUBLIC_${s}_${suf}`), 'warn', `NEXT_PUBLIC_${s}_${suf} points at a never-public credential — warn, not silence`)
    }
  }
  // The residue the verifier caught: a never-public phrase + pointer used to read
  // clean. There is no safe NEXT_PUBLIC_SERVICE_ROLE_KEY_URL, so it warns now.
  assert.equal(sev('NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_DOCS_URL'), 'warn')
  assert.equal(sev('NEXT_PUBLIC_SERVICE_ROLE_KEY_ENDPOINT'), 'warn')

  // Bare words that do NOT form config names keep their finding as a warning.
  for (const v of ['NEXT_PUBLIC_DB_CREDENTIALS_FLAG', 'NEXT_PUBLIC_SMTP_PASS_MODE']) {
    assert.equal(sev(v), 'warn', `${v} is not a config knob`)
  }
  // `GITHUB PAT` is a PHRASE, so a config word after it fails the build — a
  // GitHub personal access token is a real secret, not a knob.
  assert.equal(sev('NEXT_PUBLIC_GITHUB_PAT_TYPE'), 'fail')

  // …and the false alarms stay prevented. These are the shapes that made an
  // earlier release unusable; every one must still read clean.
  for (const v of [
    'NEXT_PUBLIC_PASSWORD_MIN_LENGTH', 'NEXT_PUBLIC_PRIVATE_BETA',
    'NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL', 'NEXT_PUBLIC_PASSWORD_RESET_URL',
    'NEXT_PUBLIC_API_KEY_HEADER', 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'NEXT_PUBLIC_ADMIN_KEYCLOAK_URL', 'NEXT_PUBLIC_SERVER_TOKENIZER_URL',
    'NEXT_PUBLIC_PADDLE_CLIENT_TOKEN', 'NEXT_PUBLIC_FIREBASE_DATABASE_URL',
  ]) assert.equal(sev(v), 'clean', `${v} is public by design`)

  // KNOWN FLOOR, asserted so it stays a decision and not drift. A bare softening
  // word (PRIVATE/PASSWORD/TOKEN) + a config word reads as a config name, so
  // `DB_PASSWORD_FLAG` clears. Documented in the README's coverage gaps.
  assert.equal(sev('NEXT_PUBLIC_DB_PASSWORD_FLAG'), 'clean')
  assert.equal(sev('NEXT_PUBLIC_DB_PASSWORD'), 'fail', 'the same name without the tail still fails')
  // A NON-softening bare word (PASS, CREDENTIALS) + a config word no longer
  // clears — it warns. The residue the inversion closed.
  assert.equal(sev('NEXT_PUBLIC_SMTP_PASS_ROTATION'), 'warn')
  assert.equal(sev('NEXT_PUBLIC_DB_CREDENTIALS_LIMIT'), 'warn')
})
