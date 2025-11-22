import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertTriangle, CheckCircle } from "lucide-react";

interface RiskScoreMeterProps {
  score: number; // 0-100
  label?: string;
  description?: string;
}

export function RiskScoreMeter({ score, label = "Risk Score", description }: RiskScoreMeterProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(score);
    }, 100);
    return () => clearTimeout(timer);
  }, [score]);

  const getRiskLevel = (value: number) => {
    if (value >= 70) return { label: "High", color: "text-destructive", bg: "bg-destructive/10", icon: AlertTriangle };
    if (value >= 40) return { label: "Medium", color: "text-warning", bg: "bg-warning/10", icon: Shield };
    return { label: "Low", color: "text-success", bg: "bg-success/10", icon: CheckCircle };
  };

  const risk = getRiskLevel(score);
  const RiskIcon = risk.icon;
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <RiskIcon className={`h-4 w-4 ${risk.color}`} />
          {label}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-4">
        <div className="relative w-32 h-32">
          <svg className="transform -rotate-90 w-32 h-32">
            <circle
              cx="64"
              cy="64"
              r="45"
              stroke="hsl(var(--muted))"
              strokeWidth="8"
              fill="none"
            />
            <circle
              cx="64"
              cy="64"
              r="45"
              stroke={score >= 70 ? "hsl(var(--destructive))" : score >= 40 ? "hsl(var(--warning))" : "hsl(var(--success))"}
              strokeWidth="8"
              fill="none"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-3xl font-bold ${risk.color}`}>{Math.round(animatedScore)}</span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
        </div>
        <div className={`${risk.bg} ${risk.color} px-3 py-1 rounded-full text-sm font-medium`}>
          {risk.label} Risk
        </div>
      </CardContent>
    </Card>
  );
}
