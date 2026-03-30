

# Fix: Email Search Hanging Issue

## Problem
Email searches take 15-20+ seconds because the `osint-search` edge function:
1. Calls 4 other edge functions **sequentially** (breach-check, dns-whois, cert-transparency, wayback) — each is a full HTTP round-trip from edge function to edge function
2. Runs 100+ subdomain DNS lookups **sequentially**
3. Does IP geolocation with **1.5s delays** between each (up to 10 IPs = 15s alone)
4. Then does SSL analysis, tech stack detection, Google dorks, email deliverability

The function eventually completes (~15-20s based on logs), but the client-side request likely times out or the user sees no feedback.

## Solution: Two-Part Fix

### Part 1 — Parallelize Everything in the Edge Function
Instead of calling sub-functions and lookups sequentially, run them in parallel using `Promise.allSettled()`:

- **Group 1 (parallel)**: breach-check, dns-whois, cert-transparency, wayback-lookup — run all 4 simultaneously instead of one after another
- **Group 2 (parallel)**: All 100+ subdomain lookups — batch into groups of 20 concurrent requests instead of one-by-one
- **Group 3 (parallel after Group 2)**: IP geolocation — remove the 1.5s delay, batch 10 IPs concurrently
- **Group 4 (parallel)**: SSL analysis + tech stack detection — run simultaneously

This should cut execution time from ~20s to ~5-8s.

### Part 2 — Add Client-Side Timeout Handling + Progress Feedback
- Increase the Supabase function invoke timeout
- Show a progress message to the user ("Analyzing domain infrastructure..." etc.) so they know it's working
- Add proper error handling for timeout scenarios with a retry option

### Files to Change

1. **`supabase/functions/osint-search/index.ts`**
   - Replace sequential sub-function calls with `Promise.allSettled()` for breach-check, dns-whois, cert-transparency, wayback-lookup
   - Batch subdomain enumeration (20 concurrent instead of 1-by-1)
   - Remove 1.5s IP geolocation delay, parallelize IP lookups
   - Run SSL + tech stack detection in parallel

2. **`src/components/SearchInterface.tsx`**
   - Add progress state showing what phase the search is in
   - Add a longer timeout or AbortController with user feedback
   - Show intermediate "Analyzing..." messages during the wait

## Expected Result
- Email searches complete in 5-8 seconds instead of 15-20+
- User sees progress feedback during the search
- No more "stuck searching" experience

