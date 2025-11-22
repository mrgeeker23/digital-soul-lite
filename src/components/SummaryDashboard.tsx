import { Card, CardContent } from "@/components/ui/card";
import { Users, Shield, Database, Globe, Activity, TrendingUp } from "lucide-react";

interface SummaryDashboardProps {
  platformsFound: number;
  platformsChecked: number;
  breachCount: number;
  subdomains: number;
  dataPoints: number;
  riskScore: number;
}

export function SummaryDashboard({
  platformsFound,
  platformsChecked,
  breachCount,
  subdomains,
  dataPoints,
  riskScore,
}: SummaryDashboardProps) {
  const stats = [
    {
      icon: Users,
      label: "Platforms Found",
      value: platformsFound,
      subtitle: `of ${platformsChecked} checked`,
      color: "text-primary",
      bg: "bg-primary/10",
    },
    {
      icon: Shield,
      label: "Breaches",
      value: breachCount,
      subtitle: breachCount > 0 ? "security alerts" : "all clear",
      color: breachCount > 0 ? "text-destructive" : "text-success",
      bg: breachCount > 0 ? "bg-destructive/10" : "bg-success/10",
    },
    {
      icon: Globe,
      label: "Subdomains",
      value: subdomains,
      subtitle: "discovered",
      color: "text-info",
      bg: "bg-info/10",
    },
    {
      icon: Database,
      label: "Data Points",
      value: dataPoints,
      subtitle: "collected",
      color: "text-chart-2",
      bg: "bg-chart-2/10",
    },
    {
      icon: TrendingUp,
      label: "Risk Score",
      value: `${riskScore}%`,
      subtitle: riskScore > 70 ? "high" : riskScore > 40 ? "medium" : "low",
      color: riskScore > 70 ? "text-destructive" : riskScore > 40 ? "text-warning" : "text-success",
      bg: riskScore > 70 ? "bg-destructive/10" : riskScore > 40 ? "bg-warning/10" : "bg-success/10",
    },
    {
      icon: Activity,
      label: "Exposure",
      value: platformsFound > 10 ? "High" : platformsFound > 5 ? "Med" : "Low",
      subtitle: "digital footprint",
      color: platformsFound > 10 ? "text-warning" : "text-info",
      bg: platformsFound > 10 ? "bg-warning/10" : "bg-info/10",
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
      {stats.map((stat, idx) => {
        const Icon = stat.icon;
        return (
          <Card
            key={idx}
            className={`${stat.bg} border-border/50 animate-slide-up hover:scale-105 transition-transform`}
            style={{ animationDelay: `${idx * 50}ms` }}
          >
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <Icon className={`h-5 w-5 ${stat.color}`} />
              </div>
              <div className={`text-3xl font-bold ${stat.color} mb-1`}>
                {stat.value}
              </div>
              <p className="text-xs text-muted-foreground font-medium">
                {stat.label}
              </p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                {stat.subtitle}
              </p>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
