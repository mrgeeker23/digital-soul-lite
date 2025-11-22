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
      console.log("Running comprehensive email-based searches...");
      
      const [localPart, domain] = query.split('@');
      
      // Email pattern intelligence
      results.findings.emailIntelligence = {
        localPart,
        domain,
        isValid: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query),
        possibleUsernames: [
          localPart,
          localPart.replace(/[._-]/g, ''),
          localPart.split(/[._-]/)[0],
          localPart.toLowerCase()
        ],
        commonVariations: [
          `${localPart}@gmail.com`,
          `${localPart}@outlook.com`,
          `${localPart}@yahoo.com`,
          `${localPart}@hotmail.com`
        ].filter(e => e !== query)
      };
      
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

      // Public footprint checks
      const footprintChecks = [
        { name: 'Gravatar', url: `https://gravatar.com/${localPart}`, type: 'profile' },
        { name: 'GitHub (email)', url: `https://api.github.com/search/users?q=${query}`, type: 'api' },
      ];

      results.findings.publicFootprint = [];
      for (const check of footprintChecks) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          
          const response = await fetch(check.url, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (response.status === 200) {
            const data = check.type === 'api' ? await response.json() : null;
            results.findings.publicFootprint.push({
              platform: check.name,
              found: true,
              url: check.url,
              data: data?.total_count > 0 ? data.items[0] : null
            });
          }
        } catch (e) {
          console.error(`${check.name} check failed:`, e);
        }
      }

      // Extract domain for additional lookups
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

        try {
          const waybackRes = await supabase.functions.invoke('wayback-lookup', {
            body: { domain }
          });
          results.findings.wayback = waybackRes.data;
        } catch (e) {
          console.error("Wayback lookup failed:", e);
        }

        // Subdomain enumeration
        console.log("Enumerating subdomains...");
        try {
          const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'staging', 'test', 'vpn', 'ssh', 'cdn', 'portal', 'app', 'mobile', 'webmail', 'secure', 'remote', 'support'];
          const subdomains = [];
          
          for (const sub of commonSubdomains) {
            try {
              const subDomain = `${sub}.${domain}`;
              const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${subDomain}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
              });
              
              if (dnsResponse.ok) {
                const dnsData = await dnsResponse.json();
                if (dnsData.Answer && dnsData.Answer.length > 0) {
                  subdomains.push({
                    subdomain: subDomain,
                    ips: dnsData.Answer.map((a: any) => a.data)
                  });
                }
              }
            } catch (e) {
              // Subdomain doesn't exist, continue
            }
          }
          
          results.findings.subdomains = {
            total: subdomains.length,
            found: subdomains
          };
          console.log(`Found ${subdomains.length} subdomains`);
        } catch (e) {
          console.error("Subdomain enumeration failed:", e);
        }

        // Technology stack detection
        console.log("Detecting technology stack...");
        try {
          const siteResponse = await fetch(`https://${domain}`, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            redirect: 'follow'
          });
          
          const headers = Object.fromEntries(siteResponse.headers.entries());
          const html = await siteResponse.text();
          
          const technologies = {
            server: headers['server'] || 'Unknown',
            poweredBy: headers['x-powered-by'] || 'Not disclosed',
            framework: null as string | null,
            cms: null as string | null,
            analytics: [] as string[],
            cdn: headers['cf-ray'] ? 'Cloudflare' : headers['x-amz-cf-id'] ? 'AWS CloudFront' : 'None detected',
            security: {
              https: siteResponse.url.startsWith('https'),
              hsts: !!headers['strict-transport-security'],
              csp: !!headers['content-security-policy'],
              xframe: headers['x-frame-options'] || 'Not set',
              xss: headers['x-xss-protection'] || 'Not set'
            }
          };

          // Detect frameworks and CMS
          if (html.includes('wp-content') || html.includes('wordpress')) technologies.cms = 'WordPress';
          if (html.includes('drupal')) technologies.cms = 'Drupal';
          if (html.includes('joomla')) technologies.cms = 'Joomla';
          if (html.includes('shopify')) technologies.cms = 'Shopify';
          if (html.includes('wix')) technologies.cms = 'Wix';
          
          if (html.includes('react')) technologies.framework = 'React';
          if (html.includes('vue')) technologies.framework = 'Vue.js';
          if (html.includes('angular')) technologies.framework = 'Angular';
          if (html.includes('next')) technologies.framework = 'Next.js';
          
          // Detect analytics
          if (html.includes('google-analytics') || html.includes('gtag')) technologies.analytics.push('Google Analytics');
          if (html.includes('facebook.com/tr')) technologies.analytics.push('Facebook Pixel');
          if (html.includes('hotjar')) technologies.analytics.push('Hotjar');
          if (html.includes('mixpanel')) technologies.analytics.push('Mixpanel');

          results.findings.techStack = technologies;
        } catch (e) {
          console.error("Tech stack detection failed:", e);
        }
      }
    }

    // Username searches - COMPREHENSIVE multi-platform check
    if (type === 'username') {
      console.log("Running comprehensive username-based searches across 47+ platforms...");
      
      // Pastebin and paste site searches
      console.log("Searching paste sites...");
      const pasteSites = [
        { name: 'Pastebin', url: `https://pastebin.com/u/${query}`, type: 'profile' },
        { name: 'GitHub Gists', url: `https://gist.github.com/${query}`, type: 'profile' },
        { name: 'Ghostbin', url: `https://ghostbin.co/paste/${query}`, type: 'paste' },
      ];

      results.findings.pasteSites = [];
      for (const site of pasteSites) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          
          const response = await fetch(site.url, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (response.status === 200) {
            const html = await response.text();
            const notFound = html.toLowerCase().includes('not found') || 
                           html.toLowerCase().includes('no pastes') ||
                           html.toLowerCase().includes('404');
            
            if (!notFound) {
              results.findings.pasteSites.push({
                platform: site.name,
                found: true,
                url: site.url,
                note: 'Potential data exposure found'
              });
            }
          }
        } catch (e) {
          console.error(`${site.name} check failed:`, e);
        }
      }
      
      const platforms = [
        // Social Media (15 platforms)
        { name: 'GitHub', url: `https://api.github.com/users/${query}`, type: 'api' },
        { name: 'Reddit', url: `https://www.reddit.com/user/${query}/about.json`, type: 'api' },
        { name: 'Instagram', url: `https://www.instagram.com/${query}/?__a=1`, type: 'web' },
        { name: 'Twitter/X', url: `https://twitter.com/${query}`, type: 'web' },
        { name: 'TikTok', url: `https://www.tiktok.com/@${query}`, type: 'web' },
        { name: 'YouTube', url: `https://www.youtube.com/@${query}`, type: 'web' },
        { name: 'Twitch', url: `https://www.twitch.tv/${query}`, type: 'web' },
        { name: 'Medium', url: `https://medium.com/@${query}`, type: 'web' },
        { name: 'Dev.to', url: `https://dev.to/${query}`, type: 'web' },
        { name: 'Snapchat', url: `https://www.snapchat.com/add/${query}`, type: 'web' },
        { name: 'Facebook', url: `https://www.facebook.com/${query}`, type: 'web' },
        { name: 'Telegram', url: `https://t.me/${query}`, type: 'web' },
        { name: 'Discord', url: `https://discord.com/users/${query}`, type: 'web' },
        { name: 'Mastodon', url: `https://mastodon.social/@${query}`, type: 'web' },
        { name: 'Bluesky', url: `https://bsky.app/profile/${query}`, type: 'web' },
        
        // Professional (8 platforms)
        { name: 'LinkedIn', url: `https://www.linkedin.com/in/${query}`, type: 'web' },
        { name: 'AngelList', url: `https://angel.co/u/${query}`, type: 'web' },
        { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${query}`, type: 'web' },
        { name: 'StackOverflow', url: `https://stackoverflow.com/users/${query}`, type: 'web' },
        { name: 'GitLab', url: `https://gitlab.com/${query}`, type: 'web' },
        { name: 'Bitbucket', url: `https://bitbucket.org/${query}`, type: 'web' },
        { name: 'Codepen', url: `https://codepen.io/${query}`, type: 'web' },
        { name: 'Kaggle', url: `https://www.kaggle.com/${query}`, type: 'web' },
        
        // Gaming (6 platforms)
        { name: 'Steam', url: `https://steamcommunity.com/id/${query}`, type: 'web' },
        { name: 'Discord.bio', url: `https://discord.bio/p/${query}`, type: 'web' },
        { name: 'Roblox', url: `https://www.roblox.com/users/profile?username=${query}`, type: 'web' },
        { name: 'Epic Games', url: `https://www.epicgames.com/id/${query}`, type: 'web' },
        { name: 'Xbox', url: `https://www.xbox.com/en-US/Profile?Gamertag=${query}`, type: 'web' },
        { name: 'PlayStation', url: `https://psnprofiles.com/${query}`, type: 'web' },
        
        // Content & Creative (10 platforms)
        { name: 'Pinterest', url: `https://www.pinterest.com/${query}`, type: 'web' },
        { name: 'Flickr', url: `https://www.flickr.com/people/${query}`, type: 'web' },
        { name: 'Vimeo', url: `https://vimeo.com/${query}`, type: 'web' },
        { name: 'SoundCloud', url: `https://soundcloud.com/${query}`, type: 'web' },
        { name: 'Behance', url: `https://www.behance.net/${query}`, type: 'web' },
        { name: 'Dribbble', url: `https://dribbble.com/${query}`, type: 'web' },
        { name: 'DeviantArt', url: `https://www.deviantart.com/${query}`, type: 'web' },
        { name: 'ArtStation', url: `https://www.artstation.com/${query}`, type: 'web' },
        { name: 'Spotify', url: `https://open.spotify.com/user/${query}`, type: 'web' },
        { name: 'Patreon', url: `https://www.patreon.com/${query}`, type: 'web' },
        
        // Forums & Communities (8 platforms)
        { name: 'Quora', url: `https://www.quora.com/profile/${query}`, type: 'web' },
        { name: 'ProductHunt', url: `https://www.producthunt.com/@${query}`, type: 'web' },
        { name: 'About.me', url: `https://about.me/${query}`, type: 'web' },
        { name: 'Keybase', url: `https://keybase.io/${query}`, type: 'web' },
        { name: 'Linktree', url: `https://linktr.ee/${query}`, type: 'web' },
        { name: 'Gravatar', url: `https://en.gravatar.com/${query}`, type: 'web' },
        { name: 'WordPress', url: `https://${query}.wordpress.com`, type: 'web' },
        { name: 'Blogger', url: `https://${query}.blogspot.com`, type: 'web' },
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
      
      // Social graph mapping
      console.log("Mapping social graph connections...");
      const socialGraph: any = {
        username: query,
        connections: [],
        commonThemes: new Set(),
        estimatedActivity: 'Unknown'
      };

      foundPlatforms.forEach((platform: any) => {
        if (platform.found) {
          socialGraph.connections.push({
            platform: platform.platform,
            url: platform.profileUrl,
            hasAvatar: !!platform.avatarUrl,
            hasBio: !!(platform.bio || platform.description)
          });

          // Extract themes from bios
          if (platform.bio) {
            const keywords = ['developer', 'designer', 'artist', 'gamer', 'creator', 'entrepreneur', 'student', 'engineer'];
            keywords.forEach(keyword => {
              if (platform.bio.toLowerCase().includes(keyword)) {
                socialGraph.commonThemes.add(keyword);
              }
            });
          }
        }
      });

      socialGraph.commonThemes = Array.from(socialGraph.commonThemes);
      
      // Estimate activity level
      const activityScore = foundPlatforms.length;
      if (activityScore >= 15) socialGraph.estimatedActivity = 'Very Active';
      else if (activityScore >= 8) socialGraph.estimatedActivity = 'Active';
      else if (activityScore >= 3) socialGraph.estimatedActivity = 'Moderate';
      else socialGraph.estimatedActivity = 'Low';

      results.findings.socialGraph = socialGraph;

      // Dark web monitoring indicators
      console.log("Checking dark web exposure indicators...");
      const darkWebIndicators = {
        breachExposure: results.findings.breaches?.error ? 'Unknown' : 'Check breach data',
        pasteExposure: (results.findings.pasteSites?.length || 0) > 0 ? 'Found' : 'None detected',
        riskLevel: 'Low',
        recommendations: [] as string[]
      };

      // Calculate risk level
      const riskFactors = [
        discoveredEmails.size > 0,
        (results.findings.pasteSites?.length || 0) > 0,
        foundPlatforms.length > 20,
        foundPlatforms.some((p: any) => p.email)
      ].filter(Boolean).length;

      if (riskFactors >= 3) {
        darkWebIndicators.riskLevel = 'High';
        darkWebIndicators.recommendations.push('Consider using unique passwords per service');
        darkWebIndicators.recommendations.push('Enable 2FA on all accounts');
        darkWebIndicators.recommendations.push('Review and limit public information exposure');
      } else if (riskFactors >= 1) {
        darkWebIndicators.riskLevel = 'Medium';
        darkWebIndicators.recommendations.push('Enable 2FA where available');
        darkWebIndicators.recommendations.push('Regular password updates recommended');
      } else {
        darkWebIndicators.recommendations.push('Maintain good security practices');
      }

      results.findings.darkWebIndicators = darkWebIndicators;

      // Calculate data richness score
      const dataRichnessScore = Math.round(
        (foundPlatforms.length / platforms.length) * 30 +
        (discoveredEmails.size > 0 ? 20 : 0) +
        (foundPlatforms.some((p: any) => p.avatarUrl) ? 15 : 0) +
        (foundPlatforms.some((p: any) => p.bio || p.description) ? 20 : 0) +
        (foundPlatforms.some((p: any) => p.location) ? 15 : 0)
      );

      results.findings.dataRichnessScore = dataRichnessScore;
      results.findings.summary = {
        totalPlatforms: platforms.length,
        foundPlatforms: foundPlatforms.length,
        discoveredEmails: discoveredEmails.size,
        pasteSitesChecked: results.findings.pasteSites?.length || 0,
        richness: dataRichnessScore >= 70 ? 'High' : dataRichnessScore >= 40 ? 'Medium' : 'Low',
        socialActivity: socialGraph.estimatedActivity,
        riskLevel: darkWebIndicators.riskLevel
      };
      
      console.log(`Found ${foundPlatforms.length}/${platforms.length} platforms for ${query}`);
      console.log(`Discovered ${discoveredEmails.size} emails from profiles`);
      console.log(`Data richness score: ${dataRichnessScore}/100`);
      console.log(`Risk level: ${darkWebIndicators.riskLevel}`);
    }

    // Phone searches
    if (type === 'phone') {
      console.log("Running comprehensive phone-based searches...");
      
      // Clean phone number
      const cleaned = query.replace(/\D/g, '');
      
      // Basic validation and formatting
      const phoneIntelligence: any = {
        original: query,
        cleaned,
        isValid: cleaned.length >= 10 && cleaned.length <= 15,
        length: cleaned.length
      };

      // Detect country code
      if (cleaned.startsWith('1') && cleaned.length === 11) {
        phoneIntelligence.country = 'US/Canada';
        phoneIntelligence.countryCode = '+1';
        phoneIntelligence.formatted = `+1 (${cleaned.substring(1, 4)}) ${cleaned.substring(4, 7)}-${cleaned.substring(7)}`;
      } else if (cleaned.startsWith('44')) {
        phoneIntelligence.country = 'UK';
        phoneIntelligence.countryCode = '+44';
      } else if (cleaned.startsWith('91')) {
        phoneIntelligence.country = 'India';
        phoneIntelligence.countryCode = '+91';
      } else if (cleaned.startsWith('86')) {
        phoneIntelligence.country = 'China';
        phoneIntelligence.countryCode = '+86';
      } else if (cleaned.startsWith('61')) {
        phoneIntelligence.country = 'Australia';
        phoneIntelligence.countryCode = '+61';
      }

      // Spam report checks
      const spamChecks = [
        { name: 'WhoCalledMe', url: `https://whocalled.me/${cleaned}` },
        { name: 'CallerId', url: `https://calleridtest.com/number/${cleaned}` }
      ];

      phoneIntelligence.spamReports = [];
      for (const check of spamChecks) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          
          const response = await fetch(check.url, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (response.status === 200) {
            const html = await response.text();
            phoneIntelligence.spamReports.push({
              platform: check.name,
              found: !html.toLowerCase().includes('not found'),
              url: check.url
            });
          }
        } catch (e) {
          console.error(`${check.name} check failed:`, e);
        }
      }

      results.findings.phone = phoneIntelligence;
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
