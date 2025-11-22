import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network, ExternalLink } from "lucide-react";

interface NetworkNode {
  platform: string;
  username?: string;
  url?: string;
  followers?: number;
  connectionStrength: number; // 0-100
}

interface NetworkGraphCardProps {
  centerNode: string;
  connections: NetworkNode[];
}

export function NetworkGraphCard({ centerNode, connections }: NetworkGraphCardProps) {
  const maxConnections = Math.min(connections.length, 8);
  const angleStep = (2 * Math.PI) / maxConnections;

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5 text-primary" />
          Social Network Graph
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative w-full aspect-square max-w-md mx-auto">
          {/* Center Node */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
            <div className="w-20 h-20 rounded-full bg-primary flex items-center justify-center shadow-lg animate-pulse-glow">
              <span className="text-xs font-bold text-primary-foreground text-center px-2 break-all">
                {centerNode.length > 15 ? centerNode.substring(0, 12) + "..." : centerNode}
              </span>
            </div>
          </div>

          {/* Connection Nodes */}
          {connections.slice(0, maxConnections).map((connection, idx) => {
            const angle = angleStep * idx;
            const radius = 120;
            const x = Math.cos(angle) * radius;
            const y = Math.sin(angle) * radius;
            
            const strengthColor = 
              connection.connectionStrength > 70 ? "bg-success" :
              connection.connectionStrength > 40 ? "bg-warning" : "bg-muted";

            return (
              <div key={idx} className="animate-fade-in" style={{ animationDelay: `${idx * 100}ms` }}>
                {/* Connection Line */}
                <svg
                  className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
                  style={{ width: "100%", height: "100%", zIndex: 0 }}
                >
                  <line
                    x1="50%"
                    y1="50%"
                    x2={`calc(50% + ${x}px)`}
                    y2={`calc(50% + ${y}px)`}
                    stroke="hsl(var(--border))"
                    strokeWidth="2"
                    strokeDasharray="4 4"
                    opacity="0.5"
                  />
                </svg>

                {/* Node */}
                <div
                  className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
                  style={{
                    transform: `translate(calc(-50% + ${x}px), calc(-50% + ${y}px))`,
                  }}
                >
                  <div className={`${strengthColor} w-16 h-16 rounded-full flex flex-col items-center justify-center shadow-lg border-2 border-background group hover:scale-110 transition-transform`}>
                    <span className="text-[10px] font-bold text-foreground text-center px-1">
                      {connection.platform}
                    </span>
                    {connection.url && (
                      <a
                        href={connection.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="opacity-0 group-hover:opacity-100 transition-opacity absolute -bottom-6"
                      >
                        <ExternalLink className="h-3 w-3 text-primary" />
                      </a>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Legend */}
        <div className="mt-8 pt-4 border-t border-border">
          <div className="flex flex-wrap gap-4 justify-center text-xs">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-success" />
              <span className="text-muted-foreground">Strong</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-warning" />
              <span className="text-muted-foreground">Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-muted" />
              <span className="text-muted-foreground">Weak</span>
            </div>
          </div>
          
          {connections.length > maxConnections && (
            <p className="text-center text-xs text-muted-foreground mt-2">
              +{connections.length - maxConnections} more connections not shown
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
