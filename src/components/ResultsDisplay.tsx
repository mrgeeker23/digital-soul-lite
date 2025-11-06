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
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {findings.socialMedia.map((platform: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-muted">
                  <div className="flex items-center gap-3">
                    {platform.found ? (
                      <CheckCircle2 className="h-5 w-5 text-success" />
                    ) : (
                      <XCircle className="h-5 w-5 text-muted-foreground" />
                    )}
                    <span className="font-medium">{platform.platform}</span>
                  </div>
                  {platform.found && platform.data && (
                    <div className="text-sm text-muted-foreground">
                      {platform.platform === 'GitHub' && platform.data.login && (
                        <span>@{platform.data.login}</span>
                      )}
                      {platform.platform === 'Reddit' && platform.data.data?.name && (
                        <span>u/{platform.data.data.name}</span>
                      )}
                    </div>
                  )}
                </div>
              ))}
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
