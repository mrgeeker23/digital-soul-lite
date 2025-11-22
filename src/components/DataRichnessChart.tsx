import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BarChart3 } from "lucide-react";

interface DataRichnessChartProps {
  categories: Array<{
    name: string;
    value: number;
    max: number;
    color?: string;
  }>;
}

export function DataRichnessChart({ categories }: DataRichnessChartProps) {
  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-primary" />
          Data Richness Analysis
        </CardTitle>
        <CardDescription>Intelligence gathered across categories</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {categories.map((category, idx) => {
          const percentage = (category.value / category.max) * 100;
          const color = category.color || "hsl(var(--primary))";
          
          return (
            <div key={idx} className="space-y-2 animate-slide-up" style={{ animationDelay: `${idx * 100}ms` }}>
              <div className="flex justify-between text-sm">
                <span className="text-foreground font-medium">{category.name}</span>
                <span className="text-muted-foreground">
                  {category.value} / {category.max}
                </span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-1000 ease-out"
                  style={{
                    width: `${percentage}%`,
                    backgroundColor: color,
                  }}
                />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
