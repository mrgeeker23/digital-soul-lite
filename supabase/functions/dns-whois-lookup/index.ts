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

    console.log(`Looking up DNS/WHOIS for: ${domain}`);

    // DNS lookup using Cloudflare DNS-over-HTTPS
    const dnsResponse = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: {
          'Accept': 'application/dns-json',
        },
      }
    );

    const dnsData = await dnsResponse.json();

    // WHOIS lookup using whoisxmlapi free tier (limited)
    let whoisData = null;
    try {
      const whoisResponse = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`
      );
      whoisData = await whoisResponse.json();
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : 'Unknown error';
      console.log("WHOIS lookup failed:", errorMessage);
    }

    console.log(`DNS/WHOIS lookup complete for ${domain}`);

    return new Response(
      JSON.stringify({ 
        dns: dnsData,
        whois: whoisData,
        domain 
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('DNS/WHOIS lookup error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
