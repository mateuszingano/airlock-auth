// Report layer — graded severity, copy-paste fix, and AI-ready markdown.
// Same bar as the Airlock Monitor: name the fix, don't just flag the problem.

const LEVELS = {
  public_secret: 'critical', // a secret in the client bundle
  unauth_mutation: 'high',
  unverified_webhook: 'high',
}
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }
const EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' }

export function levelOf(rule) {
  return LEVELS[rule] || 'medium'
}
export function levelLabel(level) {
  return LABEL[level] || String(level).toUpperCase()
}

/** The exact code / steps to seal this finding. */
export function fixFor(f) {
  switch (f.rule) {
    case 'public_secret': {
      const bare = String(f.object).replace(/^NEXT_PUBLIC_/, '')
      return `// NEXT_PUBLIC_ is inlined into the client bundle. Drop the prefix and\n// read it ONLY in server code (route handler / server action / middleware):\n//   .env      ${bare}=...\n//   server    const key = process.env.${bare}\n// Then ROTATE the key — it may already be exposed.`
    }
    case 'unauth_mutation':
      return `// Authenticate the caller before mutating:\nconst { data: { user } } = await supabase.auth.getUser()\nif (!user) return new Response('Unauthorized', { status: 401 })\n// Using a custom auth helper? Tell the guard: --auth-fn yourHelperName\n// Intentionally public? Allow-list it: --allow ${(String(f.object).match(/\/\S+/) || ['<route>'])[0]}`
    case 'unverified_webhook':
      return `// Verify the provider signature before trusting the body (Stripe example):\nconst sig = req.headers.get('stripe-signature')\nconst event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET)\n// Paddle: verify the 'Paddle-Signature' HMAC. Svix: wh.verify(payload, headers).`
    default:
      return '// (no automated fix for this rule)'
  }
}

/** Add { level, fix } to every finding (mutates and returns the result). */
export function enrich(result) {
  result.findings = result.findings.map((f) => ({ ...f, level: levelOf(f.rule), fix: fixFor(f) }))
  return result
}

/** AI-ready markdown — paste into Claude / Cursor to apply the fixes. */
export function toMarkdown(result) {
  const fs = [...result.findings].sort((a, b) => (ORDER[levelOf(a.rule)] ?? 9) - (ORDER[levelOf(b.rule)] ?? 9))
  const counts = fs.reduce((m, f) => ((m[levelOf(f.rule)] = (m[levelOf(f.rule)] || 0) + 1), m), {})
  const tally = ['critical', 'high', 'medium', 'low'].filter((l) => counts[l]).map((l) => `${counts[l]} ${l}`).join(' · ') || 'none'
  const head = result.passed ? '**PASSED** — no exposed secret.' : `**FAILED** — ${result.problems} exposed secret(s).`

  let out = `# Auth Route Guard report\n\n${head}\n\nSeverity: ${tally}. ${result.files} file(s) scanned.\n`
  if (!fs.length) return out + '\n_No findings._\n'
  out += '\n## Findings\n'
  for (const f of fs) {
    const l = levelOf(f.rule)
    out += `\n### ${EMOJI[l]} ${levelLabel(l)} — \`${f.rule}\`\n`
    out += `\`${f.file}:${f.line}\` — ${f.object}\n\n> ${f.detail}\n\n**Fix:**\n\`\`\`ts\n${fixFor(f)}\n\`\`\`\n`
  }
  return out
}
