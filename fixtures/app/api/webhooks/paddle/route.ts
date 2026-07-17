// BAD: a webhook that never verifies the signature → unverified_webhook
import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  const event = await req.json()
  await fulfill(event)
  return NextResponse.json({ received: true })
}
