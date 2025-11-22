import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  ShieldAlert, 
  Globe, 
  CheckCircle2, 
  XCircle, 
  Calendar,
  Users,
  Database
} from "lucide-react";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { RiskScoreMeter } from "./RiskScoreMeter";
import { DataRichnessChart } from "./DataRichnessChart";
import { ThreatIndicators } from "./ThreatIndicators";
import { NetworkGraphCard } from "./NetworkGraphCard";
import { SummaryDashboard } from "./SummaryDashboard";

interface ResultsDisplayProps {
  results: any;
}

export function ResultsDisplay({ results }: ResultsDisplayProps) {
  if (!results) return null;

  const { query, type, timestamp, findings } = results;

  // Calculate risk score
  const calculateRiskScore = () => {
    let score = 0;
    if (findings.breaches?.found) score += findings.breaches.count * 10;
    if (findings.darkWebMonitoring?.riskLevel === "high") score += 30;
    if (findings.darkWebMonitoring?.riskLevel === "medium") score += 15;
    if (findings.exposedFiles?.found) score += 20;
    if (findings.pasteFindings?.found) score += findings.pasteFindings.count * 5;
    return Math.min(score, 100);
  };

  const riskScore = calculateRiskScore();

  // Prepare data richness categories
  const dataCategories = [
    {
      name: "Social Platforms",
      value: findings.platformsFound || 0,
      max: findings.platformsChecked || 57,
      color: "hsl(var(--chart-1))",
    },
    {
      name: "Subdomains",
      value: findings.subdomainEnumeration?.found || 0,
      max: 100,
      color: "hsl(var(--chart-2))",
    },
    {
      name: "DNS Records",
      value: findings.enhancedDNS?.recordsFound || 0,
      max: 10,
      color: "hsl(var(--chart-3))",
    },
    {
      name: "Paste Sites",
      value: findings.pasteFindings?.found ? findings.pasteFindings.count : 0,
      max: 10,
      color: "hsl(var(--chart-4))",
    },
  ];

  // Prepare network graph connections
  const networkConnections = findings.socialMedia
    ?.filter((p: any) => p.found)
    .map((p: any) => ({
      platform: p.platform,
      username: p.username,
      url: p.profileUrl,
      followers: p.followers,
      connectionStrength: p.followers > 1000 ? 80 : p.followers > 100 ? 50 : 30,
    })) || [];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Card */}
      <Card className="border-primary/20 bg-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            OSINT Analysis: {query}
          </CardTitle>
          <CardDescription>
            Type: {type} | Timestamp: {new Date(timestamp).toLocaleString()}
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Summary Dashboard */}
      {findings.socialMedia && (
        <SummaryDashboard
          platformsFound={findings.platformsFound || 0}
          platformsChecked={findings.platformsChecked || 0}
          breachCount={findings.breaches?.count || 0}
          subdomains={findings.subdomainEnumeration?.found || 0}
          dataPoints={Object.keys(findings).length}
          riskScore={riskScore}
        />
      )}

      {/* Risk Assessment and Data Visualization */}
      <div className="grid gap-6 lg:grid-cols-2">
        <RiskScoreMeter 
          score={riskScore}
          description="Overall security risk based on findings"
        />
        <DataRichnessChart categories={dataCategories} />
      </div>

      {/* Threat Indicators */}
      <ThreatIndicators
        breachCount={findings.breaches?.count || 0}
        darkWebExposure={findings.darkWebMonitoring?.indicatorsFound || false}
        exposedFiles={findings.exposedFiles?.found ? findings.exposedFiles.count : 0}
        subdomains={findings.subdomainEnumeration?.found || 0}
        sslIssues={findings.sslAnalysis?.issues || false}
        pasteFindings={findings.pasteFindings?.found ? findings.pasteFindings.count : 0}
      />

      {/* Network Graph */}
      {networkConnections.length > 0 && (
        <NetworkGraphCard
          centerNode={query}
          connections={networkConnections}
        />
      )}

      {/* Breach Data */}
      {(findings.breaches !== undefined) && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              Data Breach Analysis
              {findings.breaches === null && (
                <Badge variant="outline" className="text-xs">
                  Requires API Key
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {findings.breaches === null ? (
              <Alert className="bg-muted border-border">
                <AlertDescription>
                  Breach checking requires a Have I Been Pwned (HIBP) API key. 
                  This is a premium feature that checks if the email has been compromised in data breaches.
                </AlertDescription>
              </Alert>
            ) : findings.breaches.error ? (
              <Alert className="bg-muted border-border">
                <AlertDescription>{findings.breaches.error}</AlertDescription>
              </Alert>
            ) : findings.breaches.found ? (
              <div className="space-y-4">
                <Alert variant="destructive">
                  <ShieldAlert className="h-4 w-4" />
                  <AlertDescription>
                    Found in {findings.breaches.count} data breaches!
                  </AlertDescription>
                </Alert>
                <Accordion type="single" collapsible>
                  {findings.breaches.breaches.slice(0, 10).map((breach: any, idx: number) => (
                    <AccordionItem key={idx} value={`breach-${idx}`}>
                      <AccordionTrigger>
                        <div className="flex items-center gap-2">
                          <Badge variant="destructive">{breach.Name}</Badge>
                          <span className="text-sm text-muted-foreground">
                            {breach.BreachDate}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent>
                        <div className="space-y-2 text-sm">
                          <p>{breach.Description}</p>
                          <div className="flex flex-wrap gap-1">
                            {breach.DataClasses?.map((dataClass: string) => (
                              <Badge key={dataClass} variant="secondary">
                                {dataClass}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </div>
            ) : (
              <Alert className="bg-muted border-border">
                <CheckCircle2 className="h-4 w-4 text-success" />
                <AlertDescription>
                  No breaches found for this email address
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* Social Media Findings */}
      {findings.socialMedia && findings.socialMedia.length > 0 && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Social Media Presence
            </CardTitle>
            <CardDescription>
              Found on {findings.platformsFound || 0} out of {findings.platformsChecked || 0} platforms checked
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 md:grid-cols-2">
              {findings.socialMedia
                .filter((platform: any) => platform.found)
                .map((platform: any, idx: number) => (
                  <Card key={idx} className="bg-muted border-primary/20">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="h-4 w-4 text-success" />
                          <span className="font-semibold">{platform.platform}</span>
                        </div>
                        {platform.profileUrl && (
                          <a 
                            href={platform.profileUrl} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-xs text-primary hover:underline"
                          >
                            View →
                          </a>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm">
                      {platform.username && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Username:</span>
                          <span className="font-mono">@{platform.username}</span>
                        </div>
                      )}
                      {platform.name && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Name:</span>
                          <span>{platform.name}</span>
                        </div>
                      )}
                      {platform.bio && (
                        <div className="text-muted-foreground text-xs mt-2 p-2 bg-background rounded">
                          {platform.bio}
                        </div>
                      )}
                      {platform.location && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Location:</span>
                          <span>{platform.location}</span>
                        </div>
                      )}
                      {platform.company && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Company:</span>
                          <span>{platform.company}</span>
                        </div>
                      )}
                      {platform.followers !== undefined && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Followers:</span>
                          <span className="font-semibold">{platform.followers.toLocaleString()}</span>
                        </div>
                      )}
                      {platform.following !== undefined && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Following:</span>
                          <span>{platform.following.toLocaleString()}</span>
                        </div>
                      )}
                      {platform.karma && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Karma:</span>
                          <span className="font-semibold">{platform.karma.toLocaleString()}</span>
                        </div>
                      )}
                      {platform.publicRepos !== undefined && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Public Repos:</span>
                          <span>{platform.publicRepos}</span>
                        </div>
                      )}
                      {platform.createdAt && (
                        <div className="flex justify-between text-xs mt-2 pt-2 border-t border-border">
                          <span className="text-muted-foreground">Joined:</span>
                          <span>{new Date(platform.createdAt).toLocaleDateString()}</span>
                        </div>
                      )}
                      {platform.title && !platform.username && (
                        <div className="text-xs text-muted-foreground">
                          {platform.title}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
            </div>
            
            {/* Show platforms where user was not found */}
            <div className="mt-4 pt-4 border-t border-border">
              <p className="text-xs text-muted-foreground mb-2">Not found on:</p>
              <div className="flex flex-wrap gap-1">
                {findings.socialMedia
                  .filter((platform: any) => !platform.found)
                  .map((platform: any, idx: number) => (
                    <Badge key={idx} variant="outline" className="text-xs opacity-50">
                      {platform.platform}
                    </Badge>
                  ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* DNS/Domain Info */}
      {findings.dns && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-primary" />
              Domain Information
              <Badge variant="secondary" className="text-xs">
                Active ✓
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Domain:</span>
                <span className="font-mono font-semibold">{findings.dns.domain}</span>
              </div>
              {findings.dns.dns?.Answer && findings.dns.dns.Answer.length > 0 && (
                <div className="space-y-2">
                  <span className="text-muted-foreground font-semibold">DNS Records:</span>
                  {findings.dns.dns.Answer.map((record: any, idx: number) => (
                    <div key={idx} className="font-mono text-xs bg-muted p-3 rounded border border-border">
                      <div className="flex justify-between mb-1">
                        <span className="text-muted-foreground">Type:</span>
                        <span>{record.type || 'A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Address:</span>
                        <span className="text-primary font-semibold">{record.data}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {findings.dns.whois?.ErrorMessage && (
                <Alert className="bg-muted/50 border-border mt-2">
                  <AlertDescription className="text-xs">
                    WHOIS lookup requires premium API access
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Certificate Transparency */}
      {findings.certificates && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5 text-primary" />
              SSL Certificate Transparency
              <Badge variant="secondary" className="text-xs">
                Active ✓
              </Badge>
            </CardTitle>
            <CardDescription>
              {findings.certificates.total ? 
                `Found ${findings.certificates.total} certificates` : 
                'Certificate transparency logs'
              }
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {findings.certificates.subdomains && findings.certificates.subdomains.length > 0 && (
                <>
                  <p className="text-sm font-semibold text-muted-foreground">
                    Discovered Subdomains ({findings.certificates.subdomains.length}):
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {findings.certificates.subdomains.slice(0, 30).map((subdomain: string, idx: number) => (
                      <Badge key={idx} variant="secondary" className="font-mono text-xs">
                        {subdomain}
                      </Badge>
                    ))}
                  </div>
                  {findings.certificates.subdomains.length > 30 && (
                    <p className="text-xs text-muted-foreground italic">
                      ... and {findings.certificates.subdomains.length - 30} more
                    </p>
                  )}
                </>
              )}
              
              {findings.certificates.certificates && findings.certificates.certificates.length > 0 && (
                <div className="mt-4 pt-4 border-t border-border">
                  <p className="text-sm font-semibold text-muted-foreground mb-2">
                    Recent Certificates (showing first 5):
                  </p>
                  <div className="space-y-2">
                    {findings.certificates.certificates.slice(0, 5).map((cert: any, idx: number) => (
                      <div key={idx} className="bg-muted p-3 rounded text-xs space-y-1">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Common Name:</span>
                          <span className="font-mono">{cert.common_name}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Email:</span>
                          <span className="font-mono text-primary">{cert.name_value}</span>
                        </div>
                        <div className="flex justify-between text-muted-foreground">
                          <span>Issued:</span>
                          <span>{new Date(cert.not_before).toLocaleDateString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
