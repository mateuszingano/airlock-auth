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
// Vendors whose browser SDK key/token is public BY DESIGN (their docs put it in
// the client). Flagging these as a build-breaking secret is the false alarm that
// makes a team uninstall the gate on its first run.
const PUBLIC_OK = /ANON|PUBLISHABLE|SITEKEY|CLIENTID|CLIENTTOKEN|MEASUREMENTID|MAPBOX|MAPS|TURNSTILE|RECAPTCHA|HCAPTCHA|ALGOLIA|POSTHOG|FIREBASE|VAPID|STREAMAPIKEY|GETSTREAM|LIVEKIT|LIVEBLOCKSPUBLIC|SEGMENTWRITE|SENTRYDSN|MIXPANEL|AMPLITUDE|CONTENTFUL|CLARITY|BUGSNAG|GIPHY|TINYMCE|UNSPLASH|INTERCOM|CRISP|HOTJAR|PLAUSIBLE|FATHOM|GOOGLETAG|GTM|PUSHER|ABLY|PADDLE|STRIPEPUBLISH/

// A mutating export in an App Router route handler.
// Every way Next.js accepts a route handler export, not just the two most
// common. The old pattern knew `export function POST` and `export const POST =`
// and nothing else, so the idiomatic ways to share one handler across verbs —
// `export { handler as POST }` and `export const { POST } = handlers` — were
// invisible. That is exactly where a mutating method sneaks in unnoticed.
const MUTATION_VERBS = 'POST|PUT|PATCH|DELETE'
const MUTATION_PATTERNS = [
  // export [async] function POST(...)   |   export const POST = ...
  new RegExp(String.raw`(?:export\s+(?:async\s+)?function\s+|export\s+const\s+)(${MUTATION_VERBS})\b`, 'g'),
  // export { handler as POST, handler as DELETE }   |   export { POST }
  new RegExp(String.raw`export\s*\{[^}]*?\b(?:as\s+)?(${MUTATION_VERBS})\b[^}]*?\}`, 'g'),
  // export const { POST, DELETE } = handlers   |   export let { PUT } = x
  new RegExp(String.raw`export\s+(?:const|let|var)\s*\{[^}]*?\b(${MUTATION_VERBS})\b[^}]*?\}`, 'g'),
]

/**
 * Build the auth-signal matcher, folding in the user's own helper names.
 *
 * Each custom name is anchored at word boundaries AND required to be CALLED, for
 * the same reason the built-in helpers are: naming a function is not invoking
 * it. Without the boundary, `--auth-fn e` turned every letter `e` in the file
 * into an auth signal and silently cleared the entire project — a one-character
 * typo that disables the scanner with no warning. Names shorter than three
 * characters are refused outright: no real helper is named `db` or `e`, and the
 * blast radius of accepting one is the whole scan.
 */
function buildAuthRe(authFns = []) {
  const usable = authFns.map((f) => String(f).trim()).filter((f) => f.length >= 3)
  if (!usable.length) return AUTH
  // Same CALL shape as the built-ins, so a user's helper called with a type
  // argument (`meuPortao<T>(req)`) counts too.
  const custom = usable.map((f) => String.raw`\b${escapeRe(f)}` + CALL).join('|')
  return new RegExp(`${AUTH.source}|${custom}`, 'i')
}

/** Names too short to be used as an auth-helper token (see buildAuthRe). */
export function rejectedAuthFns(authFns = []) {
  return authFns.map((f) => String(f).trim()).filter((f) => f && f.length < 3)
}

/** All mutating verbs this file exports as route handlers, in any export form. */
function mutatingExports(text) {
  const found = new Set()
  for (const re of MUTATION_PATTERNS) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(text))) {
      // A `{ … }` export can name several verbs at once — collect them all.
      for (const v of m[0].match(new RegExp(String.raw`\b(?:${MUTATION_VERBS})\b`, 'g')) || []) found.add(v)
    }
  }
  return [...found]
}

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
// NOTE: tested against string-blanked code (see stripJsComments's blankStrings),
// so a signal that only appears inside a string literal never counts.
// `getToken(` and a bare `.auth` were REMOVED: both are overloaded (a CSRF/captcha
// token read, an unrelated `.auth` property) and silently cleared real unguarded
// routes. `.auth` now requires an actual method call (supabase.auth.getUser()).
//
// EVERY alternative must end in an actual CALL — `\s*\(`. The centralized-helper
// group used to match the bare NAME, so merely having the identifier present
// cleared the route: an `import { requireUser } from '@/lib/auth'` that was never
// called made an unguarded handler look guarded, and a local variable named
// `checkUserAgent` did the same via `check…User`. An auth helper that is imported
// and not invoked is precisely the bug this tool should be finding.
// "Is called" in TypeScript may carry a type argument between the name and the
// parenthesis: `resolverAcessoEscrita<{ familia_id: string }>(supabase)`. A bare
// `\s*\(` misses that, and in a real TS codebase it misses a LOT — measured on
// the ZINGUI.LAR app: warnings went 2 → 38, and 34 of those were routes that DO
// call their auth helper, just generically. That is the false alarm this product
// says gets a gate uninstalled on day one.
// The inner class excludes `<`/`>` so it cannot run away across an expression.
const CALL = String.raw`\s*(?:<[^<>]{0,120}>)?\s*\(`
const AUTH = new RegExp(
  [
    `getUser${CALL}`, `getSession${CALL}`, `getServerSession${CALL}`, `currentUser${CALL}`, `getAuth${CALL}`,
    String.raw`\bauth\s*\(\s*\)`, `isAuthenticated${CALL}`, String.raw`\.auth\.\w+${CALL}`,
    String.raw`\b(?:authorize|protectRoute|protect|restrictTo|mustBeLoggedIn|can)${CALL}`,
    String.raw`\b(?:require|ensure|assert|check|verify|resolve|guard|with)\w{0,40}(?:Auth|User|Session|Access|Acesso|Permiss|Autoriz|Membro|Owner|Login|Ident|Escrita)\w{0,20}${CALL}`,
  ].join('|'),
  'i'
)


// Signals that a webhook actually VERIFIES its payload signature. This must be a
// real verification operation — merely mentioning "signature" (e.g. reading the
// `paddle-signature` header and ignoring it) is exactly the unverified webhook
// this rule exists to catch, so the bare words `signature`/`verified`/`hmac` are
// deliberately NOT accepted.
// The bare `.verify(` alternative was removed. It cleared a webhook on ANY
// object with that method — a `schema.verify(body)` payload validation, a
// `jwt.verify()` from an unrelated concern — so a route that never checked the
// provider signature looked verified. A receiver that plausibly holds the
// signature (`wh`, `webhook`, `svix`, `crypto`, `stripe`, …) still counts, and
// so does any qualified verify-name.
const SIGVERIFY = /constructEvent\s*\(|createHmac\s*\(|createVerify\s*\(|timingSafeEqual\s*\(|crypto\.subtle\.verify\s*\(|\bsvix\b|new\s+Webhook\s*\(|\b(?:wh|webhook|svix|crypto|stripe|paddle|clerk|signature|sig)\w{0,20}\.verify\s*\(|verify(?:Signature|Webhook|Event|Payload|Header)\s*\(|(?:validate|isValid|check)Signature\s*\(|\.unmarshal\s*\(/i

// A route is a webhook by its PATH. Beyond the literal word, a provider-qualified
// callback/notify/inbound endpoint is one too (/api/stripe/callback,
// /api/paddle/notify). A BARE /auth/callback is NOT — that is the OAuth return
// leg, and calling it an unverified webhook would be a false alarm.
const WEBHOOK_PATH =
  /webhook|\/hooks?\/|(?:stripe|paddle|svix|clerk|lemonsqueezy|shopify|github|gitlab|twilio|sendgrid|resend|mailgun|postmark|slack|discord)[-_/]?(?:callback|notify|notification|events?|inbound)/i
function isWebhookPath(file) {
  return WEBHOOK_PATH.test(norm(file))
}

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

/**
 * The suffix as its WORD SEGMENTS: `SERVICE_ROLE_KEY_V2` → [SERVICE, ROLE, KEY, V2].
 *
 * Gluing everything (canonicalSuffix) destroyed exactly the information needed to
 * tell `TOKEN_IZER` from `TOKENIZER`, which is why the patterns had to be anchored
 * to the END of the string — and that anchor is what let ANY trailing segment
 * disarm the whole scanner. `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_V2` was
 * invisible, and so were `_NEW`, `_PROD`, `_BACKUP`, `_PEM` and a bare digit:
 * the most natural naming conventions in existence, against the single rule that
 * could fail a build.
 */
function suffixSegments(s) {
  return s
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2') // APIKey → API_Key
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .filter(Boolean)
}

/**
 * Does a secret phrase appear in this suffix? → `'no'` | `'ambiguous'` | `'yes'`
 *
 * Three-valued on purpose. The tail after a secret word decides the verdict, and
 * a tail we cannot read confidently must not be answered with silence — see
 * isHarmlessTail.
 *
 * Two matching modes, because they have different false-positive profiles:
 *
 *  · PHRASES are multi-word and distinctive (SERVICEROLE, APIKEY, DATABASEURL).
 *    They are matched against the GLUED form, so `SERVICE_ROLE_KEY_V2`,
 *    `serviceRoleKey` and `SERVICEROLEKEY` all hit. A phrase that long does not
 *    occur inside an innocent word, so substring matching is safe here.
 *
 *  · WORDS are single and short (TOKEN, KEY, SECRET). These must match a WHOLE
 *    SEGMENT and never a substring — that is what keeps `SERVER_TOKENIZER_URL`
 *    and `ADMIN_KEYCLOAK_URL` from being flagged, which was the reason the
 *    end-anchor existed in the first place. Segment matching gives that
 *    protection without caring what comes after.
 */
function matchesSecret(suffix, { phrases, words }, { neverPublic = false } = {}) {
  const segs = suffixSegments(suffix)
  const glued = canonicalSuffix(suffix)

  // What follows the secret words decides whether this is the SECRET or metadata
  // ABOUT one. `API_KEY_NAME` / `SECRET_HEADER` name a field; `API_KEY_V2` /
  // `SECRET_PROD` are the thing itself. Distinguishing the two is what lets the
  // versioned suffixes be caught without re-flagging public config — the old
  // end-anchor could not tell them apart, so it rejected BOTH.
  // Words that mean the variable holds something ABOUT a secret rather than the
  // secret: a URL, a label, a number, a piece of UI text. A credential is never
  // called `..._DOCS_URL` or `..._HELP_LINK`.
  // Words that say the name POINTS AT or DESCRIBES a credential rather than
  // holding one. `SECRET_DOCS_URL` is a link; `API_KEY_HEADER` is a header name.
  const POINTER_TAIL = new Set([
    // names/describes one
    'NAME', 'ID', 'LABEL', 'HEADER', 'FIELD', 'PARAM',
    'PLACEHOLDER', 'EXAMPLE', 'HINT', 'TITLE', 'DESCRIPTION',
    // points at one
    'URL', 'URI', 'LINK', 'HREF', 'PATH', 'ENDPOINT', 'DOCS', 'DOC', 'PAGE', 'HELP',
    // says something about one
    'TEXT', 'MESSAGE', 'MSG', 'COPY', 'ERROR', 'PROMPT', 'POLICY', 'RULES',
    'REGEX', 'PATTERN', 'STRENGTH', 'FORMAT',
  ])

  // Words that CONFIGURE something — a duration, a toggle, an environment, a
  // bound. These never say the name points elsewhere. Keeping `ROTATION`,
  // `REFRESH`, `REQUIRED`, `LIMIT` and `PER` on the pointer list is what left
  // `NEXT_PUBLIC_CRON_SECRET_ROTATION` reading clean after two rounds of fixes:
  // a rotation setting is not a link, and Vercel's own docs name that variable.
  const CONFIG_TAIL = new Set([
    'MODE', 'TYPE', 'PREFIX', 'MAX', 'MIN', 'COUNT', 'BETA', 'FLAG', 'RESET',
    'ENABLED', 'DISABLED', 'LENGTH', 'SECONDS', 'SECS', 'MS', 'MINUTES', 'HOURS',
    'DAYS', 'AGE', 'INTERVAL', 'EXPIRY', 'EXPIRES', 'TTL', 'TIMEOUT',
    'PER', 'LIMIT', 'RETRIES', 'DISPLAY', 'REQUIRED', 'REFRESH', 'ROTATION',
  ])

  // What the tail after a secret word means — and the reason this is not a
  // boolean.
  //
  // The first attempt required ALL tail segments to be known-safe, which made
  // `PASSWORD_RESET_URL` and `SECRETS_DOCS_URL` build-breaking CRITICALs telling
  // the reader to ROTATE a docs link. An exhaustive list of harmless words does
  // not exist, so "every word must be known-safe" fails on the first unlisted
  // one — and there is always an unlisted one.
  //
  // The fix for that was `.some()` over the WHOLE tail, and it went too far the
  // other way: ONE known-safe word ANYWHERE downstream cleared the name, so
  // `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_MAX` shipped a service_role key past
  // the single rule that can fail a build. A gate whose headline promise is
  // "fails the build on a NEXT_PUBLIC_ secret" may not be disarmed by a trailing
  // word.
  //
  // So silence must be earned rather than assumed — see the inverted default in
  // isHarmlessTail. The versioned-suffix scar stays closed either way: `V2`,
  // `NEW`, `PROD` and `BACKUP` say nothing about pointing anywhere, so
  // `SERVICE_ROLE_KEY_V2` is still a fail.
  // `strength` is what keeps this from swapping one false alarm for another.
  // A PHRASE (`SERVICE ROLE`, `API KEY`, `DATABASE URL`) names a credential and
  // nothing else — no config knob is called "service role", so a config word
  // after it does not make it config. A bare WORD (`PRIVATE`, `PASSWORD`,
  // `TOKEN`, `SECRET`) is ordinary English that modifies the noun after it:
  // `PRIVATE_BETA` is a feature flag, `PASSWORD_MIN_LENGTH` is a form rule.
  // Same tail word, opposite meaning, decided by what it trails.
  // Nouns that FINISH the credential's name rather than start its tail:
  // `SERVICE ROLE` matches at ROLE, but the name is `SERVICE_ROLE_KEY`, so the
  // real tail begins after KEY. Without this, `SERVICE_ROLE_KEY_MAX` was judged
  // on a tail of [KEY, MAX] — MAX only downstream — and came out `ambiguous`
  // when it is flatly a service_role key.
  const CREDENTIAL_NOUN = new Set(['KEY', 'KEYS', 'TOKEN', 'TOKENS', 'SECRET', 'SECRETS', 'CREDENTIAL', 'CREDENTIALS', 'PASSWORD', 'PASSWORDS', 'PAT'])

  // The only bare secret words that form genuine config names in English (see
  // the CONFIG_TAIL branch below). Every other bare word keeps its finding.
  const SOFTENING_WORDS = new Set(['PRIVATE', 'PASSWORD', 'PASSWORDS', 'TOKEN', 'TOKENS'])

  const isHarmlessTail = (from0, strength, matchedWord) => {
    let from = from0
    while (from < segs.length && CREDENTIAL_NOUN.has(segs[from])) from++
    const tail = segs.slice(from)
    if (tail.length === 0) return 'yes'
    const known = (seg) => POINTER_TAIL.has(seg) || CONFIG_TAIL.has(seg)

    // THE DEFAULT IS INVERTED, and that inversion is the whole design.
    //
    // Three rounds of this same bug taught it. The old shape was "clear the
    // finding, UNLESS one of these branches objects", and each round closed one
    // branch while the next stayed open: `.some()` over the whole tail let
    // `SERVICE_ROLE_KEY_MAX` through; narrowing to position 1 left
    // `SERVICE_ROLE_KEY_ROTATION`; guarding hard phrases left `CRON_SECRET_ROTATION`
    // and the entire soft set. A rule that must be blindfolded one hole at a time
    // is the wrong rule, and the next hole is always the one nobody listed.
    //
    // So silence is now EARNED, and only two things earn it:

    // (1) A bare SOFTENING word (PRIVATE/PASSWORD/TOKEN) + any known word forms a
    // genuine English config or descriptor name: `PRIVATE_BETA` is a flag,
    // `PASSWORD_MIN_LENGTH` a form rule, `TOKEN_ENDPOINT` the OAuth token URL,
    // `PASSWORD_RESET_URL` a link. Only those three words qualify — `SECRET`,
    // `PASS`, `CREDENTIAL`, `PAT` do NOT form config names, so a bare
    // `CRON_SECRET_ROTATION` / `REVALIDATE_SECRET_ENDPOINT` is NOT cleared here.
    if (strength === 'word' && SOFTENING_WORDS.has(matchedWord) && known(tail[0])) return 'no'

    // (2) A TRUE POINTER word immediately after a credential PHRASE — URL, DOCS,
    // HEADER, NAME — clears the finding when the phrase is one that CAN name a
    // legitimately public value: `API_KEY_HEADER` is a header name, and a public
    // browser API key is a real thing.
    //
    // A phrase that has NO public form (`SERVICE_ROLE`, `PRIVATE_KEY`,
    // `MASTER_KEY`, every `*_SECRET`, a `DATABASE_URL`) does NOT get cleared by a
    // pointer: there is no `NEXT_PUBLIC_SERVICE_ROLE_KEY_URL` that is safe, so
    // `_URL`/`_ENDPOINT`/`_PATH` after it is genuinely ambiguous, not proof it
    // points away. Those warn. `neverPublic` is true exactly for the HARD set.
    if (strength === 'phrase' && POINTER_TAIL.has(tail[0])) return neverPublic ? 'ambiguous' : 'no'

    // A config word after a credential PHRASE is still the credential and breaks
    // the build: no public variable is named "service role" or "webhook secret",
    // whatever trails it. `SERVICE_ROLE_KEY_ROTATION` and `_MAX` both fail. The
    // words that broke this before (ROTATION, REFRESH, LIMIT, PER, REQUIRED) are
    // config, not pointers — a key's rotation setting is still about the key.
    if (strength === 'phrase' && CONFIG_TAIL.has(tail[0])) return 'yes'

    // Everything else that touches a known word cannot be proven either way — a
    // config word after a bare hard secret (`CRON_SECRET_ROTATION`), a pointer
    // after a bare hard secret (`SECRET_ENDPOINT`), a known word only downstream.
    // Warn, never silence.
    if (tail.some(known)) return 'ambiguous'
    return 'yes'
  }

  // A phrase matches when its words appear as CONSECUTIVE whole segments.
  // Substring-on-glued would be too loose: `ADMIN_KEYCLOAK_URL` contains
  // "ADMINKEY" and `SERVER_TOKENIZER_URL` contains "SERVERTOKEN" — flagging
  // those is exactly the false alarm the end-anchor was protecting against.
  // A plural is the same secret. `SECRETS`, `API_KEYS`, `TOKENS`, `PASSWORDS`
  // all read clean because every comparison was exact — eleven real secrets in
  // the measured sample, missed on an `S`.
  const sameWord = (seg, w) => seg === w || (seg !== undefined && seg === `${w}S`)
  const runEndsAt = (wordsOfPhrase) => {
    for (let i = 0; i + wordsOfPhrase.length <= segs.length; i++) {
      if (wordsOfPhrase.every((w, k) => sameWord(segs[i + k], w))) return i + wordsOfPhrase.length
    }
    return -1
  }
  // The strongest verdict any phrase/word produces wins: one unambiguous hit is
  // enough, and an ambiguous hit still beats silence.
  let verdict = 'no'
  const raise = (v) => { if (v === 'yes') verdict = 'yes'; else if (v === 'ambiguous' && verdict === 'no') verdict = 'ambiguous' }

  for (const p of phrases) {
    const end = runEndsAt(p.words)
    if (end !== -1) raise(isHarmlessTail(end, 'phrase'))
    // Fallback for a name written with NO separators at all (`SERVICEROLEKEY`):
    // there are no segments to reason about, so a glued substring is the only
    // signal available.
    if (segs.length === 1 && glued.includes(p.glued)) raise('yes')
  }
  const at = segs.findIndex((seg) => words.some((w) => sameWord(seg, w)))
  if (at !== -1) raise(isHarmlessTail(at + 1, 'word', segs[at]))
  return verdict
}

/** `'SERVICE ROLE'` → `{ words: ['SERVICE','ROLE'], glued: 'SERVICEROLE' }` */
const phrase = (s) => ({ words: s.split(' '), glued: s.replace(/ /g, '') })

const VENDOR_KEYS = ['ANTHROPIC', 'OPENAI', 'OPENROUTER', 'GROQ', 'MISTRAL', 'COHERE', 'REPLICATE', 'HUGGINGFACE', 'PERPLEXITY', 'DEEPSEEK', 'TOGETHER', 'GEMINI', 'XAI'].map((v) => phrase(`${v} KEY`))

// Anything that reads as a server secret.
const SECRETY_MATCH = {
  phrases: [phrase('SERVICE ROLE'), phrase('SVC ROLE'), phrase('SERVICE KEY'), phrase('API KEY'), phrase('ACCESS KEY'), phrase('DATABASE URL'), phrase('DATABASE URI'), phrase('MONGODB URI'), phrase('MONGO URL'), phrase('REDIS URL'), phrase('POSTGRES URL'), phrase('CONNECTION STRING'), phrase('SECRET KEY'), phrase('SECRET TOKEN'), phrase('PRIVATE KEY'), phrase('PRIVATE TOKEN'), phrase('STRIPE SK'), phrase('GITHUB PAT'), ...VENDOR_KEYS],
  // PASS is how SMTP_PASS / DB_PASS are written in practice; PAT is a personal
  // access token. Both were missed because only the long spellings were listed.
  words: ['SECRET', 'PRIVATE', 'PASSWORD', 'PASSWD', 'PASS', 'CREDENTIAL', 'CREDENTIALS', 'TOKEN', 'ENCRYPTION', 'SIGNING', 'PAT'],
}

// The strong set the public-vendor allow-list may never wave through.
// ADMIN/SERVER/MASTER only ever appear as PHRASES with a KEY/TOKEN companion, so
// a plain ADMIN_URL or ADMIN_EMAIL stays clean while ADMIN_KEY is caught.
// The `<thing> SECRET` / `<thing> KEY` names below are PHRASES, not bare words,
// and that distinction is load-bearing: only a phrase resists the tail amnesty.
// Left as bare words, the most ordinary credential names in a Next.js app —
// `JWT_SECRET`, `WEBHOOK_SECRET`, `SESSION_SECRET`, `CLIENT_SECRET`,
// `ENCRYPTION_KEY`, `SIGNING_SECRET` — were silenced outright by any config or
// pointer word after them, so `NEXT_PUBLIC_STRIPE_WEBHOOK_SIGNING_SECRET_MODE`
// read clean while the README promised to catch exactly that.
// The build-breaking (fail) set: names that NO vendor ships in the browser on
// purpose. Two kinds live here now:
//  - the credential phrases above (service_role, *_SECRET, private/master key…);
//  - connection strings and provider secret keys that are secret BY THE NOUN,
//    regardless of vendor: a `POSTGRES_URL`, a `CONNECTION_STRING`, a `MONGODB_URI`,
//    an LLM-provider key, a `STRIPE_SK`, a `GITHUB_PAT`. These moved up from the
//    soft set so the README's promise ("connection string, LLM key → fail") holds.
// Deliberately NOT here (they stay a `warn`, see SECRETY_MATCH): a generic
// `*_API_KEY`, a bare `DATABASE_URL`, a bare `ACCESS_KEY`. Alchemy/Infura/Weglot
// ship a public browser `*_API_KEY`, a `DATABASE_URL` may be Firebase's public
// one, and Unsplash ships a public `ACCESS_KEY` — failing those breaks a real
// project's CI on day one, the exact false alarm this tool exists to avoid. The
// line is the NOUN, not a vendor allow-list: "postgres url" is never public,
// "database url" might be; a `*_SECRET`/`SK`/`PAT` never is, a bare "access key"
// might be. AWS's genuine secret (`AWS_SECRET_ACCESS_KEY`) is still caught — by
// the bare word SECRET, not by "access key".
const HARD_SECRET_MATCH = {
  phrases: [phrase('SERVICE ROLE'), phrase('SVC ROLE'), phrase('SERVICE KEY'), phrase('SECRET KEY'), phrase('SECRET TOKEN'), phrase('PRIVATE KEY'), phrase('PRIVATE TOKEN'), phrase('ADMIN KEY'), phrase('ADMIN TOKEN'), phrase('SERVER KEY'), phrase('SERVER TOKEN'), phrase('MASTER KEY'), phrase('MASTER TOKEN'), phrase('ENCRYPTION KEY'), phrase('ENCRYPTION SECRET'), phrase('SIGNING KEY'), phrase('SIGNING SECRET'), phrase('WEBHOOK SECRET'), phrase('SESSION SECRET'), phrase('JWT SECRET'), phrase('AUTH SECRET'), phrase('NEXTAUTH SECRET'), phrase('CLIENT SECRET'), phrase('APP SECRET'), phrase('REFRESH TOKEN'), phrase('CONNECTION STRING'), phrase('MONGODB URI'), phrase('MONGO URL'), phrase('REDIS URL'), phrase('POSTGRES URL'), phrase('STRIPE SK'), phrase('GITHUB PAT'), ...VENDOR_KEYS],
  words: ['PRIVATE', 'PASSWORD', 'PASSWD', 'PASS', 'SECRET', 'SIGNING', 'ENCRYPTION', 'CREDENTIAL', 'CREDENTIALS'],
}

// Strip JS/TS comments so a comment ("// TODO: verify signature") can't fake a
// signal — while keeping STRING contents intact (a `//` inside "https://..." or
// "//cdn" is not a comment, and must not swallow a secret on the same line) and
// preserving newlines so line numbers stay accurate. A tiny scanner that tracks
// ' " ` strings with escapes; regex-literal edge cases are out of scope.
// Tokens after which a `/` starts a REGEX LITERAL rather than a division. This
// is the one genuinely ambiguous character in JS lexing, and getting it wrong is
// what broke this scanner: `const Q = /['"]/g` had its `'` read as the start of a
// string, which then never closed, so the ENTIRE REST OF THE FILE was blanked.
// The consequences ran both ways — a real `export function POST` after it became
// invisible (false negative), and a route that DID call getUser() lost its auth
// signal and got flagged (false positive).
//
// A `/` is division only after something that can END an expression: an
// identifier, a number, a closing `)`/`]`, or a string. Keywords are the trap —
// `return /re/.test(x)` is a regex, and `return` is an identifier-shaped token —
// so the ones that can be followed by an expression are listed explicitly.
const REGEX_OK_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw',
  'case', 'do', 'else', 'yield', 'await', 'if', 'while', 'for', 'switch', 'and', 'or', 'not',
])

/**
 * Neutralize everything that is not executable code, so a signal found in the
 * result is a signal in real code.
 *
 * Handles line comments, block comments, single/double-quoted strings, template
 * literals INCLUDING their `${…}` interpolations (which hold real code and must
 * survive), and regex literals. Offsets and line numbers are preserved exactly:
 * every construct is replaced by the same number of characters, with newlines
 * kept, so `line` in a finding still points at the right source line.
 *
 * `state` (optional out-param) receives `{ unterminated }` when the file ends
 * inside a string, template or block comment. That means everything after the
 * opener was blanked and never analyzed — the caller must report the file as
 * skipped rather than as clean, for the same reason a gate may not approve text
 * it could not read.
 */
export function stripJsComments(src, { blankStrings = false } = {}, state) {
  const parts = []
  let i = 0
  const n = src.length
  // Last significant (non-whitespace, non-comment) character emitted, plus the
  // identifier that ended there — together they decide regex vs division.
  let lastSig = ''
  let lastWord = ''
  // Stack so a `${…}` inside a template can itself contain a template.
  const templateStack = []
  let unterminated = null

  const push = (s) => parts.push(s)
  const blankRun = (from, to) => {
    for (let j = from; j < to; j++) push(src[j] === '\n' ? '\n' : ' ')
  }
  const noteSig = (ch) => {
    if (/\s/.test(ch)) return
    lastSig = ch
    if (/[A-Za-z0-9_$]/.test(ch)) lastWord += ch
    else lastWord = ''
  }

  while (i < n) {
    const c = src[i]
    const c2 = src[i + 1]

    // Closing a template's `${…}` — back into template text.
    if (c === '}' && templateStack.length && templateStack[templateStack.length - 1].inExpr) {
      templateStack[templateStack.length - 1].inExpr = false
      push('}')
      i++
      lastSig = '}'
      lastWord = ''
      continue
    }

    // Inside template TEXT (not an interpolation).
    if (templateStack.length && !templateStack[templateStack.length - 1].inExpr) {
      if (c === '\\') { push(blankStrings ? '  ' : src.slice(i, i + 2)); i += 2; continue }
      if (c === '`') { templateStack.pop(); push('`'); i++; lastSig = '`'; lastWord = ''; continue }
      if (c === '$' && c2 === '{') {
        templateStack[templateStack.length - 1].inExpr = true
        push('${')
        i += 2
        lastSig = '{'
        lastWord = ''
        continue
      }
      push(blankStrings ? (c === '\n' ? '\n' : ' ') : c)
      i++
      continue
    }

    if (c === '/' && c2 === '/') {
      while (i < n && src[i] !== '\n') { push(' '); i++ }
      continue
    }
    if (c === '/' && c2 === '*') {
      const start = i
      i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++
      if (i >= n) { unterminated = unterminated || 'block comment'; blankRun(start, n); i = n; continue }
      i += 2
      blankRun(start, i)
      continue
    }

    // Regex literal. Blank its contents so a quote or a keyword inside can never
    // be mistaken for code, and so it cannot leave a string state open.
    if (c === '/' && startsRegex(lastSig, lastWord)) {
      const start = i
      let j = i + 1
      let inClass = false
      let closed = false
      while (j < n) {
        const ch = src[j]
        if (ch === '\\') { j += 2; continue }
        if (ch === '\n') break // an unterminated regex cannot span lines — treat as division
        if (ch === '[') inClass = true
        else if (ch === ']') inClass = false
        else if (ch === '/' && !inClass) { closed = true; j++; break }
        j++
      }
      if (closed) {
        while (j < n && /[a-z]/i.test(src[j])) j++ // flags
        blankRun(start, j)
        i = j
        lastSig = '/'
        lastWord = ''
        continue
      }
      // Not a regex after all — fall through and treat `/` as an operator.
    }

    if (c === '`') {
      templateStack.push({ inExpr: false })
      push('`')
      i++
      lastSig = '`'
      lastWord = ''
      continue
    }

    if (c === "'" || c === '"') {
      const quote = c
      const start = i
      let j = i + 1
      let closed = false
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue }
        if (src[j] === '\n') break // a plain string may not span lines
        if (src[j] === quote) { closed = true; j++; break }
        j++
      }
      if (!closed) {
        unterminated = unterminated || 'string literal'
        // Blank to end of line, then carry on — do NOT swallow the rest of the
        // file. The `unterminated` flag is what tells the caller this file's
        // result is untrustworthy.
        while (j < n && src[j] !== '\n') j++
      }
      push(quote)
      if (blankStrings) blankRun(start + 1, j - (closed ? 1 : 0))
      else for (let k = start + 1; k < j - (closed ? 1 : 0); k++) push(src[k])
      if (closed) push(quote)
      i = j
      continue
    }

    push(c)
    noteSig(c)
    i++
  }

  if (templateStack.length) unterminated = unterminated || 'template literal'
  if (state) state.unterminated = unterminated
  return parts.join('')
}

/** Does a `/` at this point begin a regex literal rather than a division? */
function startsRegex(lastSig, lastWord) {
  if (!lastSig) return true // start of file
  if (lastWord && REGEX_OK_KEYWORDS.has(lastWord.toLowerCase())) return true
  if (/[A-Za-z0-9_$)\]]/.test(lastSig)) return false // ends an expression → division
  return true // after ( , = : [ ! & | ? { ; etc.
}

// Case-insensitive for the same reason as isSourceFile: on a case-insensitive
// filesystem `route.TS` is served exactly like `route.ts`.
export function isRouteFile(path) {
  return /(?:^|\/)app\/(?:.*\/)?route\.(?:t|j)sx?$/i.test(norm(path))
}

export function isEnvFile(path) {
  return /(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(norm(path))
}

// Case-insensitive: on Windows and macOS the filesystem is case-insensitive, so
// `route.TS` is a file Next.js serves exactly like `route.ts` — but this test
// rejected it, and the route vanished from the scan entirely.
export function isSourceFile(path) {
  return /\.(?:t|j)sx?$|\.mjs$|\.cjs$/i.test(norm(path))
}

// Pages Router API route — pages/api/**.ts (a lot of real Next apps still use it),
// excluding _-prefixed files (_middleware, _document, …).
export function isPagesApiFile(path) {
  const p = norm(path)
  return /(?:^|\/)(?:src\/)?pages\/api\/.*\.(?:t|j)sx?$/i.test(p) && !/(?:^|\/)_[^/]*\.(?:t|j)sx?$/i.test(p)
}

/** app/api/webhooks/paddle/route.ts → /api/webhooks/paddle */
export function routeUrl(path) {
  const p = norm(path)
  const m = /(?:^|\/)app\/(.*)\/route\.(?:t|j)sx?$/i.exec(p)
  if (!m) return p
  return '/' + m[1].replace(/\/?\(.*?\)/g, '').replace(/^\/+/, '') // strip route groups (auth)
}

/** pages/api/charge.ts → /api/charge · pages/api/user/index.ts → /api/user */
export function pagesRouteUrl(path) {
  const p = norm(path)
  const m = /(?:^|\/)(?:src\/)?pages\/api\/(.*)\.(?:t|j)sx?$/i.exec(p)
  if (!m) return p
  return '/api/' + m[1].replace(/\/index$/, '')
}

// Newline positions are indexed ONCE per text, then each lookup is a binary
// search. The previous form rescanned from character 0 on every finding, which
// is O(text × findings): measured 39ms / 417ms / 4023ms for 500 / 2000 / 8000
// matches — 4 seconds on a 490KB file, and up to ~16s at the 1MB file cap. The
// ReDoS bound in AUTH was already in place; this was the quadratic nobody had
// measured, hiding behind it.
const lineIndexFor = (text) => {
  // Memoized on the last text seen: a scan calls this many times for one file,
  // then moves on, so a single-slot cache gets the full benefit without holding
  // memory across files.
  if (lineIndexFor._text === text) return lineIndexFor._nl
  const nl = []
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') nl.push(i)
  lineIndexFor._text = text
  lineIndexFor._nl = nl
  return nl
}

function lineOf(text, index) {
  const nl = lineIndexFor(text)
  let lo = 0
  let hi = nl.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (nl[mid] < index) lo = mid + 1
    else hi = mid
  }
  return lo + 1
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
    // RAW suffix — canonicalization happens inside the matchers, which need the
    // separators to tell whole segments apart (see matchesSecret).
    const suffix = name.slice('NEXT_PUBLIC_'.length)
    if (seen.has(name)) continue
    // Two tiers, split by whether the noun can EVER be legitimately public:
    //  - HARD (service_role, *_SECRET, private/master key, connection strings,
    //    access keys, LLM keys) → fail. No vendor ships these in the browser, so
    //    a `hardV === 'yes'` breaks the build. The README's rule table promises
    //    exactly this for "access key, database URL, LLM-provider key".
    //  - SOFT (a generic *_API_KEY / *_TOKEN that is not a known-public vendor
    //    key) → warn, NOT a build break. Alchemy, Infura, Weglot ship a public
    //    browser `*_API_KEY` by design; failing those is the false alarm that
    //    gets the gate uninstalled on day one. `--fail-on warn` gates on them for
    //    teams that want it. Known-public vendor keys are exempted by PUBLIC_OK.
    //
    // AMBIGUOUS in either tier → warn: a config/pointer word downstream of the
    // secret (`CRON_SECRET_ROTATION`, `SERVICE_ROLE_KEY_URL`). We can neither
    // prove it holds the credential nor prove it points away, so it WARNS — the
    // old code answered silence here, which is how a service_role key walked past.
    const hardV = matchesSecret(suffix, HARD_SECRET_MATCH, { neverPublic: true })
    const softV = PUBLIC_OK.test(canonicalSuffix(suffix)) ? 'no' : matchesSecret(suffix, SECRETY_MATCH)
    const breaksBuild = hardV === 'yes'
    const warns = softV === 'yes' || softV === 'ambiguous' || hardV === 'ambiguous'
    if (!breaksBuild && !warns) continue
    seen.add(name)
    out.push(
      breaksBuild
        ? { rule: 'public_secret', severity: 'fail', file, line: lineOf(text, m.index), object: name, detail: `${name} is inlined into the client bundle by Next.js — a "NEXT_PUBLIC_" secret is readable by anyone. Rename it (drop NEXT_PUBLIC_) and read it server-side only.` }
        : { rule: 'public_secret', severity: 'warn', file, line: lineOf(text, m.index), object: name, detail: `${name} is inlined into the client bundle by Next.js. If this holds a server secret, rename it (drop NEXT_PUBLIC_) and read it server-side only. If it is a vendor's public browser key, allow-list it with --allow ${name}.` }
    )
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
  // Auth/verification signals are judged on CODE only — a match inside a string
  // literal is not a check (see stripJsComments's blankStrings).
  const code = stripJsComments(rawText, { blankStrings: true })
  const out = []
  const url = routeUrl(file)
  const methods = []
  for (const re of MUTATION_PATTERNS) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(text))) {
      const line = lineOf(text, m.index)
      for (const v of m[0].match(new RegExp(String.raw`\b(?:${MUTATION_VERBS})\b`, 'g')) || []) {
        if (!methods.some((x) => x.method === v)) methods.push({ method: v, line })
      }
    }
  }

  // A route is a webhook only by its PATH — never by merely mentioning the word
  // (a checkout route that references its webhook URL is not itself a webhook).
  const isWebhook = isWebhookPath(file)

  if (isWebhook) {
    if (!SIGVERIFY.test(code)) {
      out.push({ rule: 'unverified_webhook', severity: 'warn', file, line: methods[0]?.line || 1, object: url, detail: `webhook route with no signature verification — anyone who finds the URL can forge calls. Verify the provider signature before trusting the body.` })
    }
    return out
  }

  const authRe = buildAuthRe(authFns)
  // Judge each handler in its OWN segment, not the whole file.
  //
  // `authRe.test(code)` asked "does this FILE authenticate anywhere?", so a
  // `route.ts` exporting a GET that calls getUser() alongside a naked POST read
  // as clean — and that is a normal, common shape: the read path is guarded, the
  // write path is the one someone forgot. `scanServerAction` already sliced by
  // export for exactly this reason (its comment even names it "the file-level
  // false negative"); scanRoute simply never inherited the fix.
  const unguarded = []
  for (const { method, line } of methods) {
    if (isHandlerAuthed(code, method, authRe)) continue
    unguarded.push({ method, line })
  }
  if (unguarded.length) {
    const names = [...new Set(unguarded.map((x) => x.method))].join('/')
    out.push({ rule: 'unauth_mutation', severity: 'warn', file, line: unguarded[0].line, object: `${names} ${url}`, detail: `mutating handler with no auth check — confirm the caller is authorized (getUser/getSession/auth or your auth helper), or allow-list it if it is intentionally public.` })
  }
  return out
}

/**
 * Does the segment belonging to `method` contain an auth signal?
 *
 * The segment runs from this handler's export to the next top-level export (or
 * end of file). When the handler cannot be located as its own declaration — an
 * aliased re-export like `export { handler as POST }`, where the body lives
 * elsewhere in the file — we fall back to judging the whole file, because the
 * shared body genuinely is shared. Falling back keeps that case at today's
 * behaviour rather than inventing a false positive.
 */
function isHandlerAuthed(code, method, authRe) {
  const decl = new RegExp(String.raw`export\s+(?:async\s+)?(?:function\s+${method}\b|const\s+${method}\s*=)`, 'g')
  const m = decl.exec(code)
  if (!m) return authRe.test(code) // shared/aliased handler → file-level judgement
  // Next top-level export after this one bounds the segment.
  const after = new RegExp(String.raw`export\s+(?:async\s+)?(?:function|const|let|var|\{)`, 'g')
  after.lastIndex = m.index + m[0].length
  const next = after.exec(code)
  const segment = code.slice(m.index, next ? next.index : code.length)
  if (authRe.test(segment)) return true
  // The handler may delegate to a LOCAL helper declared above the exports —
  // the single most common shape in a real route file:
  //
  //   async function checkAdmin() { … supabase.auth.getUser() … }
  //   export async function GET()   { const u = await checkAdmin(); … }
  //   export async function PATCH() { const u = await checkAdmin(); … }
  //
  // Slicing per handler put that helper in NEITHER segment, so both handlers
  // read as unguarded. Measured on a real app: 3 routes newly flagged, all of
  // them genuinely guarded. The module prelude is shared by construction, so a
  // helper defined there and CALLED here counts — while an auth call sitting
  // inside a sibling HANDLER still does not, which is the bug this all fixed.
  for (const name of localAuthHelpers(code.slice(0, firstExportIndex(code)), authRe)) {
    if (new RegExp(String.raw`\b${name}\s*(?:<[^<>]{0,120}>)?\s*\(`).test(segment)) return true
  }
  return false
}

/** Offset of the first top-level export, or end of file. */
function firstExportIndex(code) {
  const m = /export\s+(?:async\s+)?(?:function|const|let|var|default|\{)/.exec(code)
  return m ? m.index : code.length
}

/** Names of functions declared in `prelude` whose body carries an auth signal. */
function localAuthHelpers(prelude, authRe) {
  const names = []
  const re = /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/g
  let m
  while ((m = re.exec(prelude))) {
    const name = m[1] || m[2]
    // Body = from this declaration to the next one (good enough: we only need to
    // know whether an auth call appears inside it).
    const start = m.index
    re.lastIndex = m.index + m[0].length
    const nextDecl = /(?:async\s+)?function\s+[A-Za-z_$]|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\(|[A-Za-z_$])/g
    nextDecl.lastIndex = m.index + m[0].length
    const nx = nextDecl.exec(prelude)
    if (authRe.test(prelude.slice(start, nx ? nx.index : prelude.length))) names.push(name)
  }
  return names
}

// A Pages Router handler ships one default export and switches on `req.method`,
// so we flag it only when it EXPLICITLY handles a mutating method (a GET-only
// handler stays silent). Webhooks are judged on the signature, same as App Router.
// A Pages Router handler declares its method in several idiomatic ways. Only
// `===`/`case` were recognized, but the NEGATIVE guard clause —
// `if (req.method !== 'POST') return res.status(405).end()` — is *the* canonical
// way to write a POST-only endpoint, and it was invisible. So was
// `req.method.toUpperCase()`. Pages Router coverage is a README claim, so half
// the idiom going unread is a promise not kept.
const PAGES_MUTATION = new RegExp(
  String.raw`(?:` +
    // req.method === 'POST'  |  req.method == "POST"  |  case 'POST':
    String.raw`req\.method(?:\.toUpperCase\(\))?\s*===?\s*|case\s+` +
    String.raw`)['"\`](post|put|patch|delete)['"\`]`,
  'i'
)

// `if (req.method !== 'GET') …` means "everything except GET is handled here",
// which includes the mutating verbs. Treated as mutating unless the excluded
// method is itself the only mutating one.
const PAGES_MUTATION_NEGATED = /req\.method(?:\.toUpperCase\(\))?\s*!==?\s*['"`](get|head|options|post|put|patch|delete)['"`]/i

export function scanPagesRoute(rawText, file, { authFns = [] } = {}) {
  const text = stripJsComments(rawText)
  const code = stripJsComments(rawText, { blankStrings: true })
  const out = []
  const url = pagesRouteUrl(file)
  const isWebhook = isWebhookPath(file)

  if (isWebhook) {
    if (!SIGVERIFY.test(code)) {
      out.push({ rule: 'unverified_webhook', severity: 'warn', file, line: 1, object: url, detail: `webhook route with no signature verification — anyone who finds the URL can forge calls. Verify the provider signature before trusting the body.` })
    }
    return out
  }

  let mut = PAGES_MUTATION.exec(text)
  if (!mut) {
    // The negative guard clause. `if (req.method !== 'POST') return 405` reads
    // "anything that is not POST stops here" — so everything BELOW it runs only
    // for POST, and the handler is POST-only. That is the canonical way to write
    // a single-verb endpoint, and it was invisible. The mirror case,
    // `!== 'GET'`, leaves a GET-only handler, which is not mutating.
    const neg = PAGES_MUTATION_NEGATED.exec(text)
    if (neg && /^(post|put|patch|delete)$/i.test(neg[1])) mut = neg
  }
  // No recognized method discrimination AT ALL, but the handler writes to the
  // database. A Pages Router default export answers EVERY verb — POST included —
  // so a handler that never looks at `req.method` and then writes is reachable
  // as a mutation by anyone who can reach the URL. Requiring a recognized
  // method-check first made "I could not read how this route dispatches" render
  // as "this route does not mutate", which is the silence this gate exists to
  // remove. A route that DOES consult `req.method` in a form we cannot parse
  // stays silent — that is a coverage gap, reported as such, not a guess.
  if (!mut && !/\breq\.method\b/.test(code)) {
    const write = dbWrite(text)
    if (write) mut = Object.assign([write[0]], { index: write.index })
  }
  if (!mut) return out // GET-only or no explicit mutating method → not flagged

  const authRe = buildAuthRe(authFns)
  if (!authRe.test(code)) {
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
  const code = stripJsComments(rawText, { blankStrings: true })
  if (!USE_SERVER.test(text)) return [] // not a Server Action file
  const authRe = buildAuthRe(authFns)
  // Slice the file into exported-function segments so an auth call in ONE action
  // doesn't clear an unauthed write in ANOTHER (the file-level false negative).
  // Each segment runs from one `export … function/const` to the next.
  //
  // The two questions need DIFFERENT views of the file, which is the same split
  // `scanRoute` already makes:
  //
  //   "does it write?"        → `text`, strings intact. Raw SQL lives inside a
  //                             string (sql`delete from …`, db.query('delete …')),
  //                             so blanking strings would hide real writes.
  //   "does it authenticate?" → `code`, string CONTENTS blanked. A string that
  //                             merely MENTIONS a helper is not a check.
  //
  // This is where `code` was computed and then never used: both tests ran on
  // `text`, so an error message reading "call requireUser() first" cleared a
  // Server Action that deleted rows — caught in a route handler, missed here.
  //
  // stripJsComments blanks in place, so offsets in the two views line up. That
  // is also why USE_SERVER reads `text`: `'use server'` IS a string.
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
    if (authRe.test(code.slice(a, b))) continue // a REAL auth call → clean
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
