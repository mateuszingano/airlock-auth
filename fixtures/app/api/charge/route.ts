// BAD: a mutating handler with no auth check → unauth_mutation
import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  const { amount, to } = await req.json()
  await transfer(amount, to)
  return NextResponse.json({ ok: true })
}
