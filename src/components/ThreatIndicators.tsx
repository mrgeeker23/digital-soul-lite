import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ShieldAlert, ShieldCheck, Database, Globe, Lock } from "lucide-react";

interface ThreatIndicatorsProps {
  breachCount?: number;
  darkWebExposure?: boolean;
  exposedFiles?: number;
  subdomains?: number;
  sslIssues?: boolean;
  pasteFindings?: number;
}

export function ThreatIndicators({
  breachCount = 0,
  darkWebExposure = false,
  exposedFiles = 0,
  subdomains = 0,
  sslIssues = false,
  pasteFindings = 0,
}: ThreatIndicatorsProps) {
  const indicators = [
    {
      icon: ShieldAlert,
      label: "Data Breaches",
      value: breachCount,
      severity: breachCount > 0 ? "critical" : "safe",
      color: breachCount > 0 ? "text-destructive" : "text-success",
      bg: breachCount > 0 ? "bg-destructive/10" : "bg-success/10",
    },
    {
      icon: Database,
      label: "Dark Web",
      value: darkWebExposure ? "Detected" : "Clear",
      severity: darkWebExposure ? "warning" : "safe",
      color: darkWebExposure ? "text-warning" : "text-success",
      bg: darkWebExposure ? "bg-warning/10" : "bg-success/10",
    },
    {
      icon: Globe,
      label: "Exposed Files",
      value: exposedFiles,
      severity: exposedFiles > 0 ? "warning" : "safe",
      color: exposedFiles > 0 ? "text-warning" : "text-success",
      bg: exposedFiles > 0 ? "bg-warning/10" : "bg-success/10",
    },
    {
      icon: Lock,
      label: "SSL/TLS",
      value: sslIssues ? "Issues" : "Secure",
      severity: sslIssues ? "warning" : "safe",
      color: sslIssues ? "text-warning" : "text-success",
      bg: sslIssues ? "bg-warning/10" : "bg-success/10",
    },
    {
      icon: AlertTriangle,
      label: "Paste Sites",
      value: pasteFindings,
      severity: pasteFindings > 0 ? "warning" : "safe",
      color: pasteFindings > 0 ? "text-warning" : "text-success",
      bg: pasteFindings > 0 ? "bg-warning/10" : "bg-success/10",
    },
    {
      icon: ShieldCheck,
      label: "Subdomains",
      value: subdomains,
      severity: "info",
      color: "text-info",
      bg: "bg-info/10",
    },
  ];

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          Threat Indicators
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {indicators.map((indicator, idx) => {
            const Icon = indicator.icon;
            return (
              <div
                key={idx}
                className={`${indicator.bg} p-4 rounded-lg border border-border/50 animate-slide-up`}
                style={{ animationDelay: `${idx * 50}ms` }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`h-4 w-4 ${indicator.color}`} />
                  <span className="text-xs text-muted-foreground font-medium">
                    {indicator.label}
                  </span>
                </div>
                <div className={`text-2xl font-bold ${indicator.color}`}>
                  {indicator.value}
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
