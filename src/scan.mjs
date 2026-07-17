// Auth Route Guard — walk a Next.js project and run the rules.

import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { scanSecrets, scanRoute, scanPagesRoute, isRouteFile, isPagesApiFile, isEnvFile, isSourceFile } from './rules.mjs'

const SKIP = new Set(['node_modules', '.next', '.git', 'dist', 'build', 'coverage', '.turbo', '.vercel'])

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
  const seenSecret = new Set() // dedupe a secret name flagged across many files

  for (const file of all) {
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
    const hit = allowSet.some((a) => a === `rule:${f.rule}` || obj.includes(a))
    ;(hit ? allowed : kept).push(f)
  }

  kept.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = kept.filter((f) => f.severity === 'fail').length
  const warnings = kept.filter((f) => f.severity === 'warn').length
  return { files: all.length, findings: kept, allowed, problems, warnings, passed: problems === 0 }
}
