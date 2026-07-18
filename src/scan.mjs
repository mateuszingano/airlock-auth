// Auth Route Guard — walk a Next.js project and run the rules.

import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { scanSecrets, scanRoute, scanPagesRoute, isRouteFile, isPagesApiFile, isEnvFile, isSourceFile } from './rules.mjs'

const SKIP = new Set(['node_modules', '.next', '.git', 'dist', 'build', 'coverage', '.turbo', '.vercel'])

// A hand-written route/env file is never this big; beyond it, the file is
// generated or minified (a bundle, a data blob) with no real auth signal, and
// scanning it only risks pathological regex time. Skipped — and reported in
// `skipped`, never silently (the brand rule: no silent caps).
const MAX_FILE_BYTES = 1_000_000

export async function collectFiles(root) {
  const out = []
  async function walk(d) {
    let entries
    try {
      entries = await readdir(d, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (e.name.startsWith('.') && !e.name.startsWith('.env')) {
        if (e.isDirectory()) continue
      }
      if (SKIP.has(e.name)) continue
      const p = join(d, e.name)
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
export async function scan({ dir, files, allow = [], authFns = [] } = {}) {
  const all = files || (await collectFiles(dir))
  let findings = []
  const skipped = []
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
    for (const f of scanSecrets(text, label)) {
      if (seenSecret.has(f.object)) continue
      seenSecret.add(f.object)
      findings.push(f)
    }
    if (isRouteFile(file)) findings.push(...scanRoute(text, label, { authFns }))
    else if (isPagesApiFile(file)) findings.push(...scanPagesRoute(text, label, { authFns }))
  }

  const allowSet = allow.map((a) => a.toLowerCase()).filter(Boolean)
  const kept = []
  const allowed = []
  for (const f of findings) {
    const obj = (f.object || '').toLowerCase()
    // Match precisely so one loose token can't wave through unrelated findings:
    //  - `rule:<name>`   → silence a whole rule (explicit, deliberate).
    //  - a FAIL (secret) → require an EXACT env-name match. A substring like
    //    `key` must NOT silence every secret whose name contains "key".
    //  - a WARN (route)  → a path token must start with `/` and appear in the
    //    object (routes are identified by path); otherwise require an exact match.
    const hit = allowSet.some((a) => {
      if (a === `rule:${f.rule}`) return true
      if (a.startsWith('rule:')) return false
      if (f.severity === 'fail') return obj === a
      if (a.startsWith('/')) return obj.includes(a)
      return obj === a
    })
    ;(hit ? allowed : kept).push(f)
  }

  kept.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = kept.filter((f) => f.severity === 'fail').length
  const warnings = kept.filter((f) => f.severity === 'warn').length
  return { files: all.length, findings: kept, allowed, skipped, problems, warnings, passed: problems === 0 }
}
