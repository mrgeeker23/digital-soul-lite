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
    const { url } = await req.json();
    
    if (!url) {
      throw new Error("URL is required");
    }

    console.log(`Checking Wayback Machine for: ${url}`);

    // Wayback Machine CDX API
    const response = await fetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}&output=json&limit=100`,
      {
        headers: {
          'User-Agent': 'DigitalSoulLite-OSINT-Tool',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Wayback API error: ${response.status}`);
    }

    const data = await response.json();
    
    // First row is headers, rest are snapshots
    const headers = data[0] as string[];
    const snapshots = data.slice(1).map((row: any[]) => {
      return headers.reduce((obj: any, header: string, index: number) => {
        obj[header] = row[index];
        return obj;
      }, {});
    });

    console.log(`Found ${snapshots.length} snapshots for ${url}`);

    return new Response(
      JSON.stringify({ 
        snapshots,
        total: snapshots.length,
        url,
        oldestSnapshot: snapshots[0]?.timestamp,
        newestSnapshot: snapshots[snapshots.length - 1]?.timestamp
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('Wayback lookup error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
