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
      findings: {},
      apisUsed: [] // Track which APIs were called
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
        results.apisUsed.push('breach-check');
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
          results.apisUsed.push('dns-whois-lookup');
        } catch (e) {
          console.error("DNS lookup failed:", e);
        }

        try {
          const certRes = await supabase.functions.invoke('cert-transparency', {
            body: { domain }
          });
          results.findings.certificates = certRes.data;
          results.apisUsed.push('cert-transparency');
        } catch (e) {
          console.error("Cert lookup failed:", e);
        }

        try {
          const waybackRes = await supabase.functions.invoke('wayback-lookup', {
            body: { domain }
          });
          results.findings.wayback = waybackRes.data;
          results.apisUsed.push('wayback-lookup');
        } catch (e) {
          console.error("Wayback lookup failed:", e);
        }

        // Expanded subdomain enumeration (100+ subdomains)
        console.log("Enumerating subdomains (100+ checks)...");
        try {
          const commonSubdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'staging', 'test', 'vpn', 'ssh', 'cdn', 'portal', 'app', 'mobile', 'webmail', 'secure', 'remote', 'support',
            'beta', 'alpha', 'demo', 'sandbox', 'qa', 'uat', 'prod', 'www2', 'old', 'new', 'backup', 'store', 'mail2', 'smtp', 'pop', 'imap', 'mx', 'ns1', 'ns2', 'dns',
            'cpanel', 'whm', 'panel', 'manage', 'dashboard', 'control', 'login', 'signin', 'signup', 'register', 'auth', 'oauth', 'sso',
            'forum', 'community', 'wiki', 'docs', 'help', 'support', 'status', 'monitoring', 'stats', 'analytics', 'metrics',
            'files', 'download', 'upload', 'assets', 'static', 'media', 'img', 'images', 'video', 'videos', 'audio',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'cache', 'queue', 'worker', 'jobs',
            'git', 'svn', 'repo', 'code', 'ci', 'jenkins', 'build', 'deploy',
            'crm', 'erp', 'hr', 'finance', 'sales', 'marketing', 'invoice', 'billing', 'payment', 'checkout',
            'track', 'tracking', 'pixel', 'tag', 'event', 'log', 'logs', 'syslog',
            'web', 'www1', 'www3', 'site', 'host', 'server', 'cloud', 'edge'
          ];
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
            found: subdomains,
            checked: commonSubdomains.length
          };
          console.log(`Found ${subdomains.length}/${commonSubdomains.length} subdomains`);
        } catch (e) {
          console.error("Subdomain enumeration failed:", e);
        }

        // Enhanced DNS Analysis (MX, TXT, SPF, DKIM, DMARC)
        console.log("Performing enhanced DNS analysis...");
        try {
          const dnsRecords: any = {
            A: [],
            MX: [],
            TXT: [],
            NS: [],
            SOA: null,
            SPF: null,
            DMARC: null,
            DKIM: null
          };

          // A records
          const aResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
          });
          if (aResponse.ok) {
            const aData = await aResponse.json();
            if (aData.Answer) {
              dnsRecords.A = aData.Answer.map((a: any) => a.data);
            }
          }

          // MX records
          const mxResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {
            headers: { 'Accept': 'application/dns-json' }
          });
          if (mxResponse.ok) {
            const mxData = await mxResponse.json();
            if (mxData.Answer) {
              dnsRecords.MX = mxData.Answer.map((mx: any) => ({
                priority: mx.data.split(' ')[0],
                server: mx.data.split(' ')[1]
              }));
            }
          }

          // TXT records (SPF, DMARC, etc.)
          const txtResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {
            headers: { 'Accept': 'application/dns-json' }
          });
          if (txtResponse.ok) {
            const txtData = await txtResponse.json();
            if (txtData.Answer) {
              dnsRecords.TXT = txtData.Answer.map((txt: any) => txt.data);
              
              // Extract SPF
              const spfRecord = dnsRecords.TXT.find((r: string) => r.includes('v=spf1'));
              if (spfRecord) dnsRecords.SPF = spfRecord;
            }
          }

          // DMARC record
          const dmarcResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`, {
            headers: { 'Accept': 'application/dns-json' }
          });
          if (dmarcResponse.ok) {
            const dmarcData = await dmarcResponse.json();
            if (dmarcData.Answer) {
              dnsRecords.DMARC = dmarcData.Answer[0]?.data;
            }
          }

          results.findings.enhancedDNS = dnsRecords;
        } catch (e) {
          console.error("Enhanced DNS analysis failed:", e);
        }

        // IP Geolocation for discovered IPs
        console.log("Performing IP geolocation...");
        try {
          const discoveredIPs = new Set<string>();
          
          // Collect IPs from subdomains
          results.findings.subdomains?.found?.forEach((sub: any) => {
            sub.ips.forEach((ip: string) => discoveredIPs.add(ip));
          });

          // Collect IPs from A records
          results.findings.enhancedDNS?.A?.forEach((ip: string) => discoveredIPs.add(ip));

          const ipInfo = [];
          for (const ip of Array.from(discoveredIPs).slice(0, 10)) { // Limit to 10 IPs
            try {
              const ipResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`);
              if (ipResponse.ok) {
                const ipData = await ipResponse.json();
                if (ipData.status === 'success') {
                  ipInfo.push({
                    ip,
                    location: `${ipData.city}, ${ipData.regionName}, ${ipData.country}`,
                    coordinates: { lat: ipData.lat, lon: ipData.lon },
                    isp: ipData.isp,
                    org: ipData.org,
                    asn: ipData.as,
                    hosting: ipData.hosting,
                    proxy: ipData.proxy,
                    timezone: ipData.timezone
                  });
                }
              }
              // Rate limit: 45 requests per minute
              await new Promise(resolve => setTimeout(resolve, 1500));
            } catch (e) {
              console.error(`IP geolocation failed for ${ip}:`, e);
            }
          }

          results.findings.ipGeolocation = {
            total: discoveredIPs.size,
            analyzed: ipInfo.length,
            details: ipInfo
          };
        } catch (e) {
          console.error("IP geolocation failed:", e);
        }

        // Email deliverability check
        console.log("Checking email deliverability...");
        try {
          const emailDeliverability: any = {
            mxRecords: results.findings.enhancedDNS?.MX?.length > 0,
            spfConfigured: !!results.findings.enhancedDNS?.SPF,
            dmarcConfigured: !!results.findings.enhancedDNS?.DMARC,
            score: 0
          };

          if (emailDeliverability.mxRecords) emailDeliverability.score += 40;
          if (emailDeliverability.spfConfigured) emailDeliverability.score += 30;
          if (emailDeliverability.dmarcConfigured) emailDeliverability.score += 30;

          emailDeliverability.rating = emailDeliverability.score >= 80 ? 'Excellent' : 
                                        emailDeliverability.score >= 50 ? 'Good' : 
                                        emailDeliverability.score >= 30 ? 'Fair' : 'Poor';

          results.findings.emailDeliverability = emailDeliverability;
        } catch (e) {
          console.error("Email deliverability check failed:", e);
        }

        // Google Dorking for exposed files
        console.log("Checking for exposed files (Google Dorks)...");
        try {
          const dorkResults: any[] = [];
          const dorks = [
            `site:${domain} filetype:pdf`,
            `site:${domain} filetype:doc`,
            `site:${domain} filetype:xls`,
            `site:${domain} filetype:sql`,
            `site:${domain} filetype:env`,
            `site:${domain} filetype:log`,
            `site:${domain} "index of /"`,
            `site:${domain} intitle:"index of" "backup"`,
            `site:${domain} ext:php inurl:config`,
            `site:${domain} inurl:admin`
          ];

          dorkResults.push(...dorks.map(dork => ({
            query: dork,
            risk: dork.includes('sql') || dork.includes('env') || dork.includes('config') ? 'High' : 
                  dork.includes('backup') || dork.includes('admin') ? 'Medium' : 'Low',
            searchUrl: `https://www.google.com/search?q=${encodeURIComponent(dork)}`
          })));

          results.findings.googleDorks = {
            total: dorks.length,
            queries: dorkResults,
            note: 'Execute search URLs manually to check for exposed files'
          };
        } catch (e) {
          console.error("Google dorking failed:", e);
        }

        // SSL/TLS Analysis
        console.log("Analyzing SSL/TLS configuration...");
        try {
          const sslResponse = await fetch(`https://${domain}`, {
            headers: { 'User-Agent': 'Mozilla/5.0' }
          });
          
          const sslInfo: any = {
            enabled: sslResponse.url.startsWith('https'),
            redirectsToHttps: !sslResponse.url.startsWith('https://www.') && sslResponse.url.startsWith('https'),
            headers: {
              strictTransportSecurity: sslResponse.headers.get('strict-transport-security'),
              contentSecurityPolicy: sslResponse.headers.get('content-security-policy'),
              xFrameOptions: sslResponse.headers.get('x-frame-options'),
              xContentTypeOptions: sslResponse.headers.get('x-content-type-options'),
              referrerPolicy: sslResponse.headers.get('referrer-policy')
            },
            score: 0
          };

          if (sslInfo.enabled) sslInfo.score += 30;
          if (sslInfo.headers.strictTransportSecurity) sslInfo.score += 25;
          if (sslInfo.headers.contentSecurityPolicy) sslInfo.score += 20;
          if (sslInfo.headers.xFrameOptions) sslInfo.score += 15;
          if (sslInfo.headers.xContentTypeOptions) sslInfo.score += 10;

          sslInfo.rating = sslInfo.score >= 80 ? 'Excellent' : 
                           sslInfo.score >= 60 ? 'Good' : 
                           sslInfo.score >= 40 ? 'Fair' : 'Poor';

          results.findings.sslAnalysis = sslInfo;
        } catch (e) {
          console.error("SSL/TLS analysis failed:", e);
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
      console.log("Running comprehensive username-based searches across 57+ platforms...");
      
      // Expanded paste site searches (10+ sites)
      console.log("Searching paste sites (10+ platforms)...");
      const pasteSites = [
        { name: 'Pastebin', url: `https://pastebin.com/u/${query}`, type: 'profile' },
        { name: 'GitHub Gists', url: `https://gist.github.com/${query}`, type: 'profile' },
        { name: 'Ghostbin', url: `https://ghostbin.co/paste/${query}`, type: 'paste' },
        { name: 'PasteSR', url: `https://paste.sr.ht/~${query}`, type: 'profile' },
        { name: 'Hastebin', url: `https://hastebin.com/${query}`, type: 'paste' },
        { name: 'JustPaste.it', url: `https://justpaste.it/${query}`, type: 'paste' },
        { name: 'Rentry', url: `https://rentry.co/${query}`, type: 'paste' },
        { name: 'Pastefy', url: `https://pastefy.app/${query}`, type: 'paste' },
        { name: 'Dpaste', url: `https://dpaste.com/${query}`, type: 'paste' },
        { name: 'Paste.ee', url: `https://paste.ee/p/${query}`, type: 'paste' }
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
        
        // International Platforms (10 platforms)
        { name: 'VK (Russia)', url: `https://vk.com/${query}`, type: 'web' },
        { name: 'Weibo (China)', url: `https://weibo.com/n/${query}`, type: 'web' },
        { name: 'Baidu Tieba (China)', url: `https://tieba.baidu.com/home/main?un=${query}`, type: 'web' },
        { name: 'Douban (China)', url: `https://www.douban.com/people/${query}`, type: 'web' },
        { name: 'QQ (China)', url: `https://user.qzone.qq.com/${query}`, type: 'web' },
        { name: 'Line (Japan)', url: `https://line.me/ti/p/${query}`, type: 'web' },
        { name: 'Naver (Korea)', url: `https://blog.naver.com/${query}`, type: 'web' },
        { name: 'Odnoklassniki (Russia)', url: `https://ok.ru/${query}`, type: 'web' },
        { name: 'Yandex Zen (Russia)', url: `https://zen.yandex.ru/@${query}`, type: 'web' },
        { name: 'Mixi (Japan)', url: `https://mixi.jp/${query}`, type: 'web' },
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

      // GitHub Code Dorks - Search for exposed secrets
      console.log("Checking GitHub for potential exposed data...");
      try {
        const githubDorks = [
          { query: `${query} password`, risk: 'High', type: 'Credentials' },
          { query: `${query} api_key OR apikey`, risk: 'High', type: 'API Keys' },
          { query: `${query} secret_key OR secret`, risk: 'High', type: 'Secrets' },
          { query: `${query} token`, risk: 'Medium', type: 'Tokens' },
          { query: `${query} .env`, risk: 'High', type: 'Environment Files' },
          { query: `${query} credentials`, risk: 'High', type: 'Credentials' },
          { query: `${query} private_key OR privatekey`, risk: 'Critical', type: 'Private Keys' },
          { query: `${query} aws_access_key_id`, risk: 'Critical', type: 'AWS Keys' },
          { query: `${query} filename:config`, risk: 'Medium', type: 'Config Files' },
          { query: `${query} extension:pem OR extension:key`, risk: 'Critical', type: 'Certificate Files' }
        ];

        results.findings.githubCodeDorks = {
          total: githubDorks.length,
          searches: githubDorks.map(dork => ({
            query: dork.query,
            risk: dork.risk,
            type: dork.type,
            searchUrl: `https://github.com/search?q=${encodeURIComponent(dork.query)}&type=code`
          })),
          note: 'Execute search URLs manually to check for exposed sensitive data in code repositories'
        };
      } catch (e) {
        console.error("GitHub code dorks failed:", e);
      }

      // EXIF/Metadata Extraction Info
      console.log("Gathering EXIF extraction capabilities...");
      try {
        const avatarUrls = foundPlatforms
          .filter((p: any) => p.avatarUrl)
          .map((p: any) => ({ platform: p.platform, url: p.avatarUrl }))
          .slice(0, 5); // Limit to 5 images

        results.findings.exifCapabilities = {
          imagesFound: avatarUrls.length,
          images: avatarUrls,
          extractableData: [
            'GPS coordinates (if present)',
            'Camera make and model',
            'Date and time taken',
            'Software used for editing',
            'Original dimensions',
            'Color space',
            'Orientation',
            'Copyright information'
          ],
          note: 'Download images manually and use EXIF extraction tools to analyze metadata'
        };
      } catch (e) {
        console.error("EXIF capabilities check failed:", e);
      }

      // Reverse Image Search Indicators
      console.log("Preparing reverse image search indicators...");
      try {
        const imageUrls = foundPlatforms
          .filter((p: any) => p.avatarUrl)
          .map((p: any) => p.avatarUrl)
          .slice(0, 5);

        results.findings.reverseImageSearch = {
          totalImages: imageUrls.length,
          images: imageUrls,
          searchEngines: [
            {
              name: 'Google Images',
              url: 'https://images.google.com',
              method: 'Upload image or paste URL'
            },
            {
              name: 'TinEye',
              url: 'https://tineye.com',
              method: 'Upload image or paste URL'
            },
            {
              name: 'Yandex Images',
              url: 'https://yandex.com/images',
              method: 'Upload image for best results'
            },
            {
              name: 'Bing Visual Search',
              url: 'https://www.bing.com/visualsearch',
              method: 'Upload or paste image URL'
            }
          ],
          note: 'Use these search engines to find where else this image appears online',
          potentialFindings: [
            'Other social media profiles',
            'Dating sites',
            'Professional networks',
            'Forums and communities',
            'News articles or blogs',
            'Stock photo sources'
          ]
        };
      } catch (e) {
        console.error("Reverse image search indicators failed:", e);
      }

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
        imagesForExif: results.findings.exifCapabilities?.imagesFound || 0,
        githubDorksGenerated: results.findings.githubCodeDorks?.total || 0,
        reverseImageSearchReady: results.findings.reverseImageSearch?.totalImages || 0,
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
