# Auth Route Guard

**The CI gate for Next.js auth mistakes.** It scans your source and fails the
build when a server secret is exposed via `NEXT_PUBLIC_*` — the leak that ships
straight into the client bundle. It also warns on mutating route handlers with
no auth check and webhook routes that never verify a signature. **No build, no
runtime, no database.**

```bash
npx airlock-auth               # scans the current project
npx airlock-auth ./apps/web
```

## What it flags

| Rule | Level | Catches |
|------|-------|---------|
| `public_secret` | fail | a server secret exposed via `NEXT_PUBLIC_*` (service role key, API key, token, access key, secret, private/signing/encryption key, master key, database URL, password, LLM-provider key) |
| `unauth_mutation` | warn | a mutating route with no auth check — App Router `route.ts` **and** Pages Router `pages/api` |
| `unauth_server_action` | warn | a Server Action (`'use server'`) that writes to the DB with no auth check |
| `unverified_webhook` | warn | a webhook route that never verifies a signature |

By default only **fail** findings break the build; warnings are printed for
review. Most rules here emit `warn` — including an unauthenticated mutation — so
without gating on them they can only ever be *printed*. Use `--fail-on warn`
(or its alias `--strict`) to make warnings break the build too, and the
`fail-on` input to do the same in the Action.

**No false alarms by design.** A `NEXT_PUBLIC_*` name that holds a server secret
(API key, token, access key, service role, secret, password, LLM-provider key) is
flagged; names that are public on purpose — `ANON_KEY`, `PUBLISHABLE`, `MAPBOX`,
Google Maps / Firebase client config, web-push `VAPID`, `TURNSTILE`, analytics /
site keys, and public client tokens/keys of common SDKs (Paddle `CLIENT_TOKEN`,
Stream, Algolia, LiveKit, Liveblocks public key, Segment write key, Sentry DSN) —
are *not*. A strong secret word (`PRIVATE`, `SECRET`, `SIGNING`, `ENCRYPTION`, or
an `ADMIN_KEY`/`ADMIN_TOKEN` / `SERVER_KEY`/`SERVER_TOKEN`) is always flagged, even
on such a vendor — so `FIREBASE_PRIVATE_KEY`, `PADDLE_CLIENT_SECRET`,
`ALGOLIA_ADMIN_KEY`, `FIREBASE_ADMIN_TOKEN` and `FCM_SERVER_KEY` are caught, while
`FIREBASE_API_KEY`, `PADDLE_CLIENT_TOKEN` and a plain `ADMIN_URL`/`SERVER_URL` are
not. (A public analytics **write** key like `SEGMENT_WRITE_KEY` is intentionally
NOT barred — those are public by design.) Read-only `GET` handlers are ignored,
and a webhook is judged on its signature check, not on "missing auth".

**Spelling-insensitive on the suffix.** Only the `NEXT_PUBLIC_` prefix is matched
exactly (Next.js inlines that spelling and no other); the suffix is *canonicalized*
before matching, so every spelling of the same name folds to one verdict — camelCase
(`serviceRoleKey`), snake (`SERVICE_ROLE_KEY`), kebab, and even ALL-CAPS glued with
no separators at all (`SERVICEROLEKEY`, `SECRETKEY`, `APIKEY`) are treated the same.
A secret can't dodge the gate by changing case or dropping its underscores.

## What it does *not* cover yet

Auth Route Guard covers the three highest-signal Next.js mistakes. These are
**not** checked yet — review them yourself (or lean on runtime auth + the Airlock
Monitor):

- **Authorization *correctness*** — it checks that an auth call is *present*, not
  that it's *right*. IDOR, tenant scoping and role checks are still on you.
- **Auth via middleware only** — a route guarded by `middleware.ts` that never
  references auth in its own file may warn; use `--auth-fn` or allow-list it.
- **Secrets exposed by other means** — only `NEXT_PUBLIC_*` names are flagged, not
  a secret hardcoded in client code or shipped some other way.
- **Read handlers** (`GET`) — a `GET` that leaks data without auth is not flagged;
  only mutations are.
- **A credential whose name ends in `PRIVATE`/`PASSWORD`/`TOKEN` + a config word.**
  The suffix is read as English. Those three words form genuine config names
  (`NEXT_PUBLIC_PRIVATE_BETA` is a feature flag, `NEXT_PUBLIC_PASSWORD_MIN_LENGTH`
  is a form rule, `NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL` is a duration), so a
  config word right after them clears the finding. The cost is real and precise:
  `NEXT_PUBLIC_DB_PASSWORD_FLAG` reads clean while `NEXT_PUBLIC_DB_PASSWORD`
  fails. **Only those words soften** — `CREDENTIALS`, `PASS` and `PAT` do not, so
  `NEXT_PUBLIC_DB_CREDENTIALS_FLAG` warns.
  A credential **phrase** (`SERVICE_ROLE`, `SECRET_KEY`, `PRIVATE_KEY`,
  `WEBHOOK_SECRET`, `JWT_SECRET`, `SIGNING_SECRET`, `ENCRYPTION_KEY`,
  `SESSION_SECRET`, `CLIENT_SECRET`, `ADMIN_KEY`, `MASTER_KEY`…) is **never**
  softened by a config word: `NEXT_PUBLIC_SERVICE_ROLE_KEY_MAX` and
  `NEXT_PUBLIC_STRIPE_WEBHOOK_SIGNING_SECRET_MODE` both fail the build.
  A **pointer** word (`URL`, `DOCS`, `ROTATION`, `LIMIT`, `PER`, `REQUIRED`…)
  right after a credential phrase downgrades it to a **warning**, not silence —
  `NEXT_PUBLIC_SERVICE_ROLE_KEY_ROTATION` warns. After a bare word it still
  clears: `NEXT_PUBLIC_SMTP_PASS_ROTATION` and `NEXT_PUBLIC_DB_CREDENTIALS_LIMIT`
  read clean. That residue is the known floor of reading names as English.
- **Pages Router method dispatch we cannot parse** — a `pages/api` handler that
  writes and never mentions `req.method` is flagged (it answers every verb). One
  that *does* consult `req.method` in a shape the matcher doesn't recognize
  (`['POST'].includes(req.method)`, a dispatch table) stays silent. That is a
  coverage gap, not a verdict — recognized shapes are `===`/`!==`/`case`, with or
  without `.toUpperCase()`.
- **Server Action write coverage** — each exported action is judged on its own
  (an auth call in one action no longer clears another). The write signal covers
  Supabase/knex (`.from(...).insert/update/delete`), Drizzle (`db.insert(...)`),
  Prisma (`prisma.x.create/update/delete`) and executed raw SQL — a Supabase
  `.rpc('...')` write (ambiguous: read or write) or another ORM's `.create()` is
  not matched.
- **Route auth is judged per HANDLER.** A `GET` that calls `getUser()` next to a
  naked `POST` in the same `route.ts` does **not** clear the `POST` — each
  exported handler is sliced out and judged on its own. (An earlier release
  judged this per file; that was a real false negative and it is closed.)
- **Directories the walker skips** are **reported** in `skipped`, never silently
  omitted. `node_modules` and dot-directories (`.next`, `.git`, `.turbo`,
  `.vercel`) are skipped at **any** depth. `dist`, `build` and `coverage` are
  skipped **only at the project root** — inside `app/`, they are legitimate
  route segments, and `app/api/build/route.ts` is a plausible privileged
  endpoint that must be checked.
- **Files over 1 MB** are skipped and reported, on the assumption that they are
  generated or minified.

**How code is read.** Comments, string literals, template literals and regex
literals are neutralized before any rule runs, so a signal that only appears
inside one of them never counts as real code. If a file ends inside an
unterminated string, template or block comment, everything after the opener was
unreadable — so that file is reported as `unparsable` and **fails** the gate. It
is never reported as clean: a security gate must not answer "clean" about text it
could not read. (This detection existed but was never wired to a caller in
earlier releases, so the promise was true of the code and false of the product.)
Type annotations
are ignored rather than parsed: this is a tokenizer, not a TypeScript compiler,
which is why the package still has **zero dependencies**.

## In CI (GitHub Actions)

```yaml
- uses: mateuszingano/airlock-auth@v1
  with:
    dir: .
    # allow: /api/health,rule:unauth_mutation
```

> `@v1` works once the first release tag is published. Until then, pin `@main`
> or run `npx --yes airlock-auth .` in a step.

## Allow-listing intentional cases

Some routes are public on purpose (a health check, a public read). Silence a
finding by route path, env name, or rule:

```bash
airlock-auth --allow "/api/health,rule:unauth_mutation"
# or: AUTH_GUARD_ALLOW=/api/health airlock-auth
```

Matching is deliberately precise so one loose token can't hide unrelated leaks:

- **`rule:<name>`** silences a whole rule (e.g. `rule:unauth_mutation`).
- **A secret (fail)** needs the **exact** env name — `--allow key` will **not**
  silence every secret whose name contains "key"; pass the full
  `NEXT_PUBLIC_…_KEY`.
- **A route (warn)** matches by **path** — a token starting with `/`
  (`/api/health`) silences that route.

Oversized files (generated/minified, > 1 MB) are skipped for bounded scan time
and listed in the report's `skipped` — never dropped silently.

## Exit codes

`0` passed · `1` an exposed secret was found · `2` usage error.

---

Part of [ShipSealed](https://shipsealed.com) — ship apps that don't leak. MIT licensed.
