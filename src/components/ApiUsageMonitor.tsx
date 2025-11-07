import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { apiRateLimiter } from "@/lib/apiRateLimiter";
import { Activity, CheckCircle2, XCircle, Lock, Crown } from "lucide-react";

export function ApiUsageMonitor() {
  const [usageStats, setUsageStats] = useState<Array<{
    apiName: string;
    config: any;
    stats: { current: number; limit: number; percentage: number };
  }>>([]);

  const refreshStats = () => {
    const stats = apiRateLimiter.getAllUsageStats();
    setUsageStats(stats);
  };

  useEffect(() => {
    refreshStats();
    
    // Refresh every 5 seconds
    const interval = setInterval(refreshStats, 5000);
    
    return () => clearInterval(interval);
  }, []);

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary" />
          API Usage Monitor
        </CardTitle>
        <CardDescription>
          Track your daily API usage limits
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {usageStats.map(({ apiName, config, stats }) => {
          const isPremium = !config.enabled && ['hunter-io', 'shodan', 'pipl', 'social-searcher'].includes(apiName);
          
          return (
            <div key={apiName} className="space-y-2 relative">
              {isPremium && (
                <div className="absolute inset-0 bg-background/60 backdrop-blur-[2px] rounded-lg z-10 flex items-center justify-center">
                  <div className="flex flex-col items-center gap-2 p-4">
                    <Crown className="h-6 w-6 text-primary" />
                    <Badge variant="default" className="gap-1">
                      <Lock className="h-3 w-3" />
                      Premium API
                    </Badge>
                    <p className="text-xs text-center text-muted-foreground">
                      Available on paid plans
                    </p>
                  </div>
                </div>
              )}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm text-foreground">
                    {config.name}
                  </span>
                  {config.enabled ? (
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">
                    {stats.current}/{stats.limit}
                  </span>
                  <Badge 
                    variant={stats.percentage >= 100 ? "destructive" : stats.percentage >= 80 ? "secondary" : "outline"}
                    className="text-xs"
                  >
                    {Math.round(stats.percentage)}%
                  </Badge>
                </div>
              </div>
              <Progress 
                value={stats.percentage} 
                className="h-2"
              />
              <p className="text-xs text-muted-foreground">
                {config.description}
              </p>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
