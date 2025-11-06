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

interface ResultsDisplayProps {
  results: any;
}

export function ResultsDisplay({ results }: ResultsDisplayProps) {
  if (!results) return null;

  const { query, type, timestamp, findings } = results;

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            Search Results: {query}
          </CardTitle>
          <CardDescription>
            Type: {type} | Timestamp: {new Date(timestamp).toLocaleString()}
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Summary Stats Card */}
      {findings.socialMedia && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Platforms Found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary">
                {findings.platformsFound || 0}
              </div>
              <p className="text-xs text-muted-foreground">
                out of {findings.platformsChecked || 0} checked
              </p>
            </CardContent>
          </Card>

          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Data Points
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary">
                {Object.keys(findings).length}
              </div>
              <p className="text-xs text-muted-foreground">
                information categories
              </p>
            </CardContent>
          </Card>

          {findings.breaches && findings.breaches.found && (
            <Card className="border-destructive/50 bg-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-destructive">
                  Security Alert
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-destructive">
                  {findings.breaches.count || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  breaches detected
                </p>
              </CardContent>
            </Card>
          )}

          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Digital Footprint
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary">
                {findings.platformsFound > 10 ? 'High' : findings.platformsFound > 5 ? 'Medium' : 'Low'}
              </div>
              <p className="text-xs text-muted-foreground">
                exposure level
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Breach Data */}
      {findings.breaches && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              Data Breach Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            {findings.breaches.error ? (
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
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Domain:</span>
                <span className="font-mono">{findings.dns.domain}</span>
              </div>
              {findings.dns.dns?.Answer && (
                <div className="space-y-1">
                  <span className="text-muted-foreground">DNS Records:</span>
                  {findings.dns.dns.Answer.map((record: any, idx: number) => (
                    <div key={idx} className="font-mono text-xs bg-muted p-2 rounded">
                      {record.data}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Certificate Transparency */}
      {findings.certificates && findings.certificates.subdomains && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5 text-primary" />
              Certificate Transparency ({findings.certificates.total} total)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Discovered Subdomains ({findings.certificates.subdomains.length}):
              </p>
              <div className="flex flex-wrap gap-1">
                {findings.certificates.subdomains.slice(0, 20).map((subdomain: string, idx: number) => (
                  <Badge key={idx} variant="secondary" className="font-mono text-xs">
                    {subdomain}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
