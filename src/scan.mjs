// Auth Route Guard — walk a Next.js project and run the rules.

import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { scanSecrets, scanRoute, scanPagesRoute, scanServerAction, isRouteFile, isPagesApiFile, isEnvFile, isSourceFile, stripJsComments } from './rules.mjs'

// Never yours, wherever it appears. (`.next`, `.git`, `.turbo`, `.vercel` are
// dot-directories and are already skipped at any depth by the rule above.)
const ALWAYS_SKIP = new Set(['node_modules'])
// Build output. Skipped at ANY depth — a monorepo keeps it at
// `apps/web/dist`, not at the root — EXCEPT inside a route tree, where `build`
// is a path segment rather than an artifact directory.
const BUILD_OUTPUT = new Set(['dist', 'build', 'coverage'])
// Route trees, where a directory named `build` means the URL /api/build.
const ROUTE_TREE = /(^|[\\/])(app|pages|src[\\/](app|pages))([\\/]|$)/

// A hand-written route/env file is never this big; beyond it, the file is
// generated or minified (a bundle, a data blob) with no real auth signal, and
// scanning it only risks pathological regex time. Skipped — and reported in
// `skipped`, never silently (the brand rule: no silent caps).
const MAX_FILE_BYTES = 1_000_000

export async function collectFiles(root, { skippedDirs = [] } = {}) {
  const out = []
  async function walk(d) {
    let entries
    try {
      entries = await readdir(d, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const p = join(d, e.name)
      if (e.name.startsWith('.') && !e.name.startsWith('.env')) {
        // A dot-directory is build/tooling output — but record it, because a
        // silently skipped tree is indistinguishable from a clean one.
        if (e.isDirectory()) { skippedDirs.push(relative(root, p) || e.name); continue }
      }
      // Two different kinds of "skip", and collapsing them caused a bug in each
      // direction:
      //
      // BUILD OUTPUT (`dist`, `build`, `coverage`) is skipped at any depth,
      // EXCEPT inside a route tree. The distinction is what the name MEANS
      // where it sits, and getting it wrong burns in both directions:
      //
      //   - Skipping it only at the project root missed every monorepo, which
      //     keeps its artifacts at `apps/web/dist`. A stale bundle then broke a
      //     clean build, pointing at generated code the developer cannot fix.
      //   - Skipping it everywhere hid `app/api/build/route.ts`, where `build`
      //     is a URL segment and the handler is a plausible privileged
      //     rebuild endpoint.
      //
      // ANY-DEPTH (`node_modules`) is never yours, wherever it appears.
      if (e.isDirectory() && ALWAYS_SKIP.has(e.name)) {
        skippedDirs.push(relative(root, p) || e.name)
        continue
      }
      if (e.isDirectory() && BUILD_OUTPUT.has(e.name) && !ROUTE_TREE.test(relative(root, d))) {
        skippedDirs.push(relative(root, p) || e.name)
        continue
      }
      if (e.isDirectory()) await walk(p)
      else if (isSourceFile(p) || isEnvFile(p)) out.push(p)
    }
  }
  await walk(root)
  return out
}

function short(file, dir) {
  if (!dir) return file.split(/[\\/]/).pop()
  return relative(dir, file) || file
}

/**
 * @param {{dir?: string, files?: string[], allow?: string[]}} opts
 * @returns {Promise<{files:number, findings:Array, allowed:Array, problems:number, warnings:number, passed:boolean}>}
 */
/**
 * Does allow-list entry `a` silence finding `f`?
 *
 * Deliberately precise, so one loose token can't wave through unrelated
 * findings:
 *  - `rule:<name>`   → silence a whole rule (explicit, deliberate).
 *  - a FAIL (secret) → require an EXACT env-name match. A substring like `key`
 *    must NOT silence every secret whose name contains "key".
 *  - a WARN (route)  → a path token must start with `/` and appear in the
 *    object (routes are identified by path); otherwise require an exact match.
 */
function matches(a, f, obj) {
  if (a === `rule:${f.rule}`) return true
  if (a.startsWith('rule:')) return false
  if (f.severity === 'fail') return obj === a
  if (a.startsWith('/')) return obj.includes(a)
  return obj === a
}

export async function scan({ dir, files, allow = [], authFns = [] } = {}) {
  // Directories the walker skipped (build output, dot-dirs) are collected and
  // reported alongside oversized files — an unscanned tree must be visible, not
  // inferred from a clean result.
  const skippedDirs = []
  const all = files || (await collectFiles(dir, { skippedDirs }))
  let findings = []
  const skipped = skippedDirs.map((d) => `${d}/ (directory)`)
  const seenSecret = new Set() // dedupe a secret name flagged across many files

  for (const file of all) {
    // Skip oversized files (generated/minified) — bounded regex time, no silent cap.
    try {
      const st = await stat(file)
      if (st.size > MAX_FILE_BYTES) { skipped.push(short(file, dir)); continue }
    } catch {
      continue // unreadable/gone → skip
    }
    const text = await readFile(file, 'utf8')
    const label = short(file, dir)

    // A file that ends INSIDE an unterminated comment, string or template was
    // never really read: everything after the opener is blanked, so a secret or
    // an unguarded handler further down simply vanishes and the file reports
    // clean. Proven: a stray `/*` above a NEXT_PUBLIC_..._SERVICE_ROLE_KEY
    // produced "✓ No exposed secrets" and exit 0.
    //
    // stripJsComments has always been able to report this through its `state`
    // out-param — and nothing ever passed one, so the detection was dead code
    // while the README promised it worked. It runs here, once per file, rather
    // than in each of the four scanners: they all strip the same text, and one
    // check cannot drift from another.
    //
    // It FAILS rather than merely landing in `skipped`, because `skipped` does
    // not affect the exit code: a security gate must not answer "clean" about
    // text it could not read.
    const strip = {}
    stripJsComments(text, {}, strip)
    if (strip.unterminated) {
      skipped.push(`${label} (unreadable: ${strip.unterminated})`)
      findings.push({
        rule: 'unparsable',
        severity: 'fail',
        file: label,
        line: 1,
        object: label,
        detail: `file ends inside an unterminated ${strip.unterminated}, so everything after it was never analyzed — a secret or an unguarded handler below that point would not be reported. Close it, then re-run.`,
      })
      continue
    }

    for (const f of scanSecrets(text, label)) {
      if (seenSecret.has(f.object)) continue
      seenSecret.add(f.object)
      findings.push(f)
    }
    if (isRouteFile(file)) findings.push(...scanRoute(text, label, { authFns }))
    else if (isPagesApiFile(file)) findings.push(...scanPagesRoute(text, label, { authFns }))
    // Server Actions can live in ANY source file — self-gated on a `'use server'`
    // directive, so this is a no-op everywhere else.
    findings.push(...scanServerAction(text, label, { authFns }))
  }

  const allowSet = allow.map((a) => a.toLowerCase()).filter(Boolean)
  const kept = []
  const allowed = []
  // Which allow-list entries actually silenced something (see staleAllows).
  const used = new Set()
  for (const f of findings) {
    const obj = (f.object || '').toLowerCase()
    const hit = allowSet.some((a) => matches(a, f, obj))
    if (hit) for (const a of allowSet) if (matches(a, f, obj)) used.add(a)
    ;(hit ? allowed : kept).push(f)
  }

  // An allow-list entry that silenced NOTHING. Always a stale suppression: the
  // route was renamed, the env var dropped, the rule name mistyped. It reads as
  // active protection-with-an-exception while the exception guards nothing — and
  // if the finding comes back under a slightly different name, the entry the
  // author believes is covering it will not. Reported, never silently accepted:
  // the same rule this scanner applies to directories it skips.
  const staleAllows = allowSet.filter((a) => !used.has(a))

  kept.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = kept.filter((f) => f.severity === 'fail').length
  const warnings = kept.filter((f) => f.severity === 'warn').length
  return { files: all.length, findings: kept, allowed, skipped, staleAllows, problems, warnings, passed: problems === 0 }
}
