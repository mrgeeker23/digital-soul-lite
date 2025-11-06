import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain } = await req.json();
    
    if (!domain) {
      throw new Error("Domain is required");
    }

    console.log(`Checking certificate transparency for: ${domain}`);

    // Certificate Transparency lookup via crt.sh
    const response = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      {
        headers: {
          'User-Agent': 'DigitalSoulLite-OSINT-Tool',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`crt.sh API error: ${response.status}`);
    }

    const certificates = await response.json();
    console.log(`Found ${certificates.length} certificates for ${domain}`);

    // Extract unique subdomains
    const subdomains = new Set<string>();
    certificates.forEach((cert: any) => {
      if (cert.name_value) {
        cert.name_value.split('\n').forEach((name: string) => {
          subdomains.add(name.trim());
        });
      }
    });

    return new Response(
      JSON.stringify({ 
        certificates: certificates.slice(0, 50), // Limit to 50 most recent
        subdomains: Array.from(subdomains),
        total: certificates.length,
        domain 
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('Certificate transparency error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
