// GOOD: a read-only GET handler is not a mutation → no finding
import { NextResponse } from 'next/server'

export async function GET() {
  return NextResponse.json({ status: 'ok' })
}
