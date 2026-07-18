#!/usr/bin/env node
// Auth Route Guard — the CI gate for Next.js auth mistakes.
//
// Scans your Next.js source and fails (exit 1) when a server secret is exposed
// via NEXT_PUBLIC_*. It also warns on mutating route handlers with no auth check
// and webhook routes that never verify a signature. No build, no runtime.
//
// Usage:
//   airlock-auth                      # scans the current project
//   airlock-auth ./apps/web
//   airlock-auth --allow "/api/health,rule:unauth_mutation"
//   airlock-auth --json
//
// Exit codes:
//   0  passed — no exposed secret
//   1  failed — a NEXT_PUBLIC_ secret is exposed
//   2  usage error (path not found)

import { access } from 'node:fs/promises'
import { scan } from '../src/scan.mjs'
import { enrich, toMarkdown, levelLabel } from '../src/report.mjs'

const RESET = '\x1b[0m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'

const DEFAULT_DIR = '.'

const HELP = `Auth Route Guard — the CI gate for Next.js auth mistakes.

Usage:
  airlock-auth [DIR] [options]

Arguments:
  DIR                Project root to scan. Default: current directory.

Options:
  --allow <tokens>   Comma-separated tokens to silence. Matches a rule
                     (rule:unauth_mutation) or any finding whose object contains
                     it (a route path / env name). Env: $AUTH_GUARD_ALLOW.
  --auth-fn <names>  Comma-separated names of your project's auth helper(s), e.g.
                     requireUser,resolverAcessoEscrita. A route that calls one is
                     treated as authenticated. Env: $AUTH_GUARD_AUTH_FNS.
  --json             Print the result as JSON (includes level + fix per finding).
  --format <fmt>     text (default) or markdown (AI-ready, with fixes to paste).
  -h, --help         Show this help.
  -v, --version      Show the version.

Rules:
  public_secret      (fail)  a server secret exposed via NEXT_PUBLIC_*
  unauth_mutation    (warn)  a POST/PUT/PATCH/DELETE route with no auth check
  unauth_server_action (warn) a Server Action ('use server') that writes with no auth
  unverified_webhook (warn)  a webhook route with no signature verification

Exit codes: 0 = passed, 1 = exposed secret, 2 = usage error.`

function splitList(v) {
  return (v || '').split(',').map((s) => s.trim()).filter(Boolean)
}

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = { dir: undefined, json: false, format: 'text', allow: [], authFns: [] }
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') opts.help = true
    else if (a === '-v' || a === '--version') opts.version = true
    else if (a === '--json') opts.json = true
    else if (a === '--format') opts.format = argv[++i]
    else if (a.startsWith('--format=')) opts.format = a.slice('--format='.length)
    else if (a === '--markdown' || a === '--md') opts.format = 'markdown'
    else if (a === '--allow') opts.allow = splitList(argv[++i])
    else if (a.startsWith('--allow=')) opts.allow = splitList(a.slice('--allow='.length))
    else if (a === '--auth-fn') opts.authFns = splitList(argv[++i])
    else if (a.startsWith('--auth-fn=')) opts.authFns = splitList(a.slice('--auth-fn='.length))
    else if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`)
    else positional.push(a)
  }
  opts.dir = positional[0] || DEFAULT_DIR
  opts.allow = [...splitList(process.env.AUTH_GUARD_ALLOW), ...opts.allow]
  opts.authFns = [...splitList(process.env.AUTH_GUARD_AUTH_FNS), ...opts.authFns]
  return opts
}

async function readVersion() {
  const { readFile } = await import('node:fs/promises')
  try {
    return JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version || '0.0.0'
  } catch {
    return '0.0.0'
  }
}

function printFinding(f, mark, color) {
  const tag = `${color}[${levelLabel(f.level)}]${RESET}`
  console.log(`    ${color}${mark}${RESET} ${tag} ${f.file}:${f.line}  ${f.object} ${DIM}— ${f.detail}${RESET}`)
  for (const line of (f.fix || '').split('\n')) console.log(`        ${DIM}${line}${RESET}`)
}

function report(r) {
  const fails = r.findings.filter((f) => f.severity === 'fail')
  const warns = r.findings.filter((f) => f.severity === 'warn')

  if (fails.length) {
    console.log(`${RED}✗ ${fails.length} exposed secret(s):${RESET}`)
    for (const f of fails) printFinding(f, '✗', RED)
  } else {
    console.log(`${GREEN}✓ No exposed secrets.${RESET}`)
  }

  if (warns.length) {
    console.log(`${YELLOW}! ${warns.length} warning(s) worth a look:${RESET}`)
    for (const f of warns) printFinding(f, '!', YELLOW)
  }

  if (r.allowed.length) console.log(`${DIM}ℹ ${r.allowed.length} finding(s) allowed by config.${RESET}`)

  if (r.passed) {
    const tail = warns.length ? ` ${DIM}(${warns.length} warning(s))${RESET}` : ''
    console.log(`\n${GREEN}Auth check passed.${RESET}${tail} ${DIM}(${r.files} file(s) scanned)${RESET}`)
  } else {
    console.log(`\n${RED}Auth check failed: ${r.problems} exposed secret(s).${RESET}`)
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.help) { console.log(HELP); return 0 }
  if (opts.version) { console.log(await readVersion()); return 0 }

  try {
    await access(opts.dir)
  } catch {
    console.error(`Path not found: "${opts.dir}".`)
    return 2
  }

  const r = enrich(await scan({ dir: opts.dir, allow: opts.allow, authFns: opts.authFns }))
  if (opts.json) console.log(JSON.stringify(r, null, 2))
  else if (opts.format === 'markdown') console.log(toMarkdown(r))
  else report(r)
  return r.passed ? 0 : 1
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof UsageError ? `${err.message}\nRun \`airlock-auth --help\`.` : err.message)
    process.exit(2)
  })
