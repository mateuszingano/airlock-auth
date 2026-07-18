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
| `unverified_webhook` | warn | a webhook route that never verifies a signature |

Only **fail** findings break the build. Warnings are printed for review.

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

**Case-insensitive on the suffix.** Only the `NEXT_PUBLIC_` prefix is matched
exactly (Next.js inlines that spelling and no other); the suffix is matched
case-insensitively — screaming-snake, lower, or camelCase all count. A camelCase
name with no separators (`NEXT_PUBLIC_serviceRoleKey`, `NEXT_PUBLIC_apiKey`) is
split at its word boundaries and normalized (`SERVICE_ROLE_KEY`, `API_KEY`) before
matching, so a secret can't dodge the gate by dropping its underscores.

## What it does *not* cover yet

Auth Route Guard covers the three highest-signal Next.js mistakes. These are
**not** checked yet — review them yourself (or lean on runtime auth + the Airlock
Monitor):

- **Server Actions** (`'use server'`) — route handlers are covered (App Router
  `route.ts` **and** Pages Router `pages/api`), but Server Actions are not yet.
- **Authorization *correctness*** — it checks that an auth call is *present*, not
  that it's *right*. IDOR, tenant scoping and role checks are still on you.
- **Auth via middleware only** — a route guarded by `middleware.ts` that never
  references auth in its own file may warn; use `--auth-fn` or allow-list it.
- **Secrets exposed by other means** — only `NEXT_PUBLIC_*` names are flagged, not
  a secret hardcoded in client code or shipped some other way.
- **Read handlers** (`GET`) — a `GET` that leaks data without auth is not flagged;
  only mutations are.

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
