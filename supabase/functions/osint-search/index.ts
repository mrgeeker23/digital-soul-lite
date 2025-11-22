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

    // Username searches - COMPREHENSIVE multi-platform check
    if (type === 'username') {
      console.log("Running comprehensive username-based searches across 15+ platforms...");
      
      const platforms = [
        // Social Media
        { name: 'GitHub', url: `https://api.github.com/users/${query}`, type: 'api' },
        { name: 'Reddit', url: `https://www.reddit.com/user/${query}/about.json`, type: 'api' },
        { name: 'Instagram', url: `https://www.instagram.com/${query}/?__a=1`, type: 'web' },
        { name: 'Twitter/X', url: `https://twitter.com/${query}`, type: 'web' },
        { name: 'TikTok', url: `https://www.tiktok.com/@${query}`, type: 'web' },
        { name: 'YouTube', url: `https://www.youtube.com/@${query}`, type: 'web' },
        { name: 'Twitch', url: `https://www.twitch.tv/${query}`, type: 'web' },
        { name: 'Medium', url: `https://medium.com/@${query}`, type: 'web' },
        { name: 'Dev.to', url: `https://dev.to/${query}`, type: 'web' },
        
        // Professional
        { name: 'LinkedIn', url: `https://www.linkedin.com/in/${query}`, type: 'web' },
        { name: 'AngelList', url: `https://angel.co/u/${query}`, type: 'web' },
        { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${query}`, type: 'web' },
        { name: 'StackOverflow', url: `https://stackoverflow.com/users/${query}`, type: 'web' },
        
        // Gaming
        { name: 'Steam', url: `https://steamcommunity.com/id/${query}`, type: 'web' },
        { name: 'Discord.bio', url: `https://discord.bio/p/${query}`, type: 'web' },
        { name: 'Roblox', url: `https://www.roblox.com/users/profile?username=${query}`, type: 'web' },
        
        // Content
        { name: 'Pinterest', url: `https://www.pinterest.com/${query}`, type: 'web' },
        { name: 'Flickr', url: `https://www.flickr.com/people/${query}`, type: 'web' },
        { name: 'Vimeo', url: `https://vimeo.com/${query}`, type: 'web' },
        { name: 'SoundCloud', url: `https://soundcloud.com/${query}`, type: 'web' },
        
        // Forums & Communities
        { name: 'Quora', url: `https://www.quora.com/profile/${query}`, type: 'web' },
        { name: 'ProductHunt', url: `https://www.producthunt.com/@${query}`, type: 'web' },
        { name: 'Behance', url: `https://www.behance.net/${query}`, type: 'web' },
        { name: 'Dribbble', url: `https://dribbble.com/${query}`, type: 'web' },
      ];

      results.findings.socialMedia = [];
      results.findings.profileDetails = {};
      results.findings.discoveredEmails = [];

      // Check all platforms in parallel for speed
      const checks = platforms.map(async (platform) => {
        try {
          // Add timeout to prevent hanging requests
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 8000);
          
          const response = await fetch(platform.url, {
            headers: { 
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.5',
              'Connection': 'keep-alive',
            },
            redirect: 'follow',
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          // More strict status checking - only accept 200 OK
          const exists = response.status === 200;
          
          let profileData: any = null;
          if (exists) {
            const contentType = response.headers.get('content-type');
            
            // API responses with JSON
            if (contentType?.includes('application/json')) {
              profileData = await response.json();
            } 
            // Web pages - check if profile exists
            else if (contentType?.includes('text/html')) {
              const html = await response.text();
              
              // Enhanced detection heuristics
              const notFoundIndicators = [
                'page not found',
                'user not found',
                'profile not found',
                'account not found',
                'sorry, this page',
                '404',
                'does not exist',
                'isn\'t available',
                'suspended account',
                'this account doesn\'t exist',
                'no longer exists',
                'couldn\'t find',
                'nothing to see here',
                'not on',
                'isn\'t on'
              ];
              
              const lowerHtml = html.toLowerCase();
              
              // Check for strong indicators profile exists
              const foundIndicators = [
                'og:type',
                'profile:username',
                'twitter:creator',
                'author',
                'article:author',
                'profile',
                'followers',
                'following',
                'posts',
                'tweets',
                'videos'
              ];
              
              const hasStrongIndicators = foundIndicators.some(indicator => 
                lowerHtml.includes(indicator)
              );
              
              const hasNotFoundIndicators = notFoundIndicators.some(indicator => 
                lowerHtml.includes(indicator)
              );
              
              // Verify minimum content length (404 pages are usually short)
              const hasSubstantialContent = html.length > 5000;
              
              // Profile exists if it has strong indicators OR substantial content AND no 404 indicators
              if ((hasStrongIndicators || hasSubstantialContent) && !hasNotFoundIndicators) {
                // Extract basic info from HTML
                const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
                const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
                const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
                
                profileData = {
                  title: ogTitleMatch?.[1] || titleMatch?.[1] || null,
                  description: descMatch?.[1] || null,
                  exists: true,
                  confidence: hasStrongIndicators ? 'high' : 'medium'
                };
              } else {
                return { platform: platform.name, found: false };
              }
            }
          }

          // Extract detailed info from known API structures
          let extractedInfo: any = { platform: platform.name, found: exists };
          
          if (exists && profileData) {
            // GitHub
            if (platform.name === 'GitHub' && profileData.login) {
              extractedInfo = {
                ...extractedInfo,
                username: profileData.login,
                name: profileData.name,
                bio: profileData.bio,
                location: profileData.location,
                company: profileData.company,
                blog: profileData.blog,
                twitter: profileData.twitter_username,
                publicRepos: profileData.public_repos,
                followers: profileData.followers,
                following: profileData.following,
                createdAt: profileData.created_at,
                avatarUrl: profileData.avatar_url,
                profileUrl: profileData.html_url,
                email: profileData.email || null
              };
              
              // Extract email if available
              if (profileData.email) {
                return { ...extractedInfo, foundEmail: profileData.email };
              }
            }
            // Reddit
            else if (platform.name === 'Reddit' && profileData.data) {
              extractedInfo = {
                ...extractedInfo,
                username: profileData.data.name,
                karma: profileData.data.total_karma,
                linkKarma: profileData.data.link_karma,
                commentKarma: profileData.data.comment_karma,
                createdAt: new Date(profileData.data.created_utc * 1000).toISOString(),
                isPremium: profileData.data.is_gold,
                avatarUrl: profileData.data.icon_img,
                profileUrl: `https://reddit.com/user/${profileData.data.name}`
              };
            }
            // Generic web profile
            else if (profileData.exists) {
              extractedInfo = {
                ...extractedInfo,
                title: profileData.title,
                description: profileData.description,
                profileUrl: platform.url
              };
            }
          }

          return extractedInfo;
        } catch (e) {
          const errorMsg = e instanceof Error ? e.message : 'Unknown error';
          console.error(`${platform.name} check failed:`, errorMsg);
          
          // Distinguish between timeout and other errors
          if (errorMsg.includes('abort')) {
            return { platform: platform.name, found: false, error: 'Timeout' };
          }
          return { platform: platform.name, found: false, error: 'Unavailable' };
        }
      });

      // Wait for all checks to complete
      results.findings.socialMedia = await Promise.all(checks);
      
      // Extract discovered emails from profiles
      const emailPattern = /[\w.-]+@[\w.-]+\.\w+/g;
      const discoveredEmails = new Set<string>();
      
      results.findings.socialMedia.forEach((platform: any) => {
        // Check for direct email field
        if (platform.foundEmail) {
          discoveredEmails.add(platform.foundEmail);
        }
        if (platform.email) {
          discoveredEmails.add(platform.email);
        }
        
        // Extract from bio/description
        if (platform.bio) {
          const bioEmails = platform.bio.match(emailPattern);
          if (bioEmails) bioEmails.forEach((e: string) => discoveredEmails.add(e));
        }
        if (platform.description) {
          const descEmails = platform.description.match(emailPattern);
          if (descEmails) descEmails.forEach((e: string) => discoveredEmails.add(e));
        }
      });
      
      // Generate potential email patterns
      const cleanQuery = query.replace('@', '');
      const commonDomains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'protonmail.com'];
      const potentialEmails = commonDomains.map(domain => `${cleanQuery}@${domain}`);
      
      results.findings.discoveredEmails = Array.from(discoveredEmails);
      results.findings.potentialEmails = potentialEmails;
      
      // Count found platforms
      const foundPlatforms = results.findings.socialMedia.filter((p: any) => p.found);
      results.findings.platformsFound = foundPlatforms.length;
      results.findings.platformsChecked = platforms.length;
      
      console.log(`Found ${foundPlatforms.length}/${platforms.length} platforms for ${query}`);
      console.log(`Discovered ${discoveredEmails.size} emails from profiles`);
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
