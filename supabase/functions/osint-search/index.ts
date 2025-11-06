import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { query, type } = await req.json();
    
    if (!query || !type) {
      throw new Error("Query and type are required");
    }

    console.log(`OSINT search: ${type} - ${query}`);

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const results: any = {
      query,
      type,
      timestamp: new Date().toISOString(),
      findings: {}
    };

    // Email-based searches
    if (type === 'email' || query.includes('@')) {
      console.log("Running email-based searches...");
      
      // Breach check
      try {
        const breachRes = await supabase.functions.invoke('breach-check', {
          body: { email: query }
        });
        results.findings.breaches = breachRes.data;
      } catch (e) {
        console.error("Breach check failed:", e);
        const errorMessage = e instanceof Error ? e.message : 'Unknown error';
        results.findings.breaches = { error: errorMessage };
      }

      // Extract domain for additional lookups
      const domain = query.split('@')[1];
      if (domain) {
        try {
          const dnsRes = await supabase.functions.invoke('dns-whois-lookup', {
            body: { domain }
          });
          results.findings.dns = dnsRes.data;
        } catch (e) {
          console.error("DNS lookup failed:", e);
        }

        try {
          const certRes = await supabase.functions.invoke('cert-transparency', {
            body: { domain }
          });
          results.findings.certificates = certRes.data;
        } catch (e) {
          console.error("Cert lookup failed:", e);
        }
      }
    }

    // Username searches
    if (type === 'username') {
      console.log("Running username-based searches...");
      
      // Check common platforms (GitHub, Twitter, etc.)
      const platforms = [
        { name: 'GitHub', url: `https://api.github.com/users/${query}` },
        { name: 'Reddit', url: `https://www.reddit.com/user/${query}/about.json` },
      ];

      results.findings.socialMedia = [];

      for (const platform of platforms) {
        try {
          const response = await fetch(platform.url, {
            headers: { 'User-Agent': 'DigitalSoulLite-OSINT-Tool' }
          });
          
          if (response.ok) {
            const data = await response.json();
            results.findings.socialMedia.push({
              platform: platform.name,
              found: true,
              data: data
            });
          } else {
            results.findings.socialMedia.push({
              platform: platform.name,
              found: false
            });
          }
        } catch (e) {
          console.error(`${platform.name} lookup failed:`, e);
        }
      }
    }

    // Phone searches
    if (type === 'phone') {
      console.log("Running phone-based searches...");
      results.findings.phone = {
        message: "Phone lookup requires additional API integration",
        formatted: query
      };
    }

    console.log("OSINT search complete");

    return new Response(
      JSON.stringify(results),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('OSINT search error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
