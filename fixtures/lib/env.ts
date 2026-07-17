// A mix of public config (fine) and one leaked secret (bad).
export const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!          // fine — public
export const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!         // fine — public by design
// BAD: the service role key must never be NEXT_PUBLIC_ → public_secret (fail)
export const admin = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
