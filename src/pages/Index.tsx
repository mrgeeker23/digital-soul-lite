import { useState } from "react";
import { SearchInterface } from "@/components/SearchInterface";
import { ResultsDisplay } from "@/components/ResultsDisplay";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Database, Shield, Activity } from "lucide-react";

const Index = () => {
  const [searchResults, setSearchResults] = useState<any>(null);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">
          Digital Footprint Intelligence
        </h1>
        <p className="text-muted-foreground">
          Comprehensive OSINT analysis platform for understanding digital exposure
        </p>
      </div>

      <SearchInterface onResults={setSearchResults} />

      {searchResults && <ResultsDisplay results={searchResults} />}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Data Sources</CardTitle>
            <Database className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12+</div>
            <p className="text-xs text-muted-foreground">Active integrations</p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Public Records</CardTitle>
            <Globe className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">Real-time</div>
            <p className="text-xs text-muted-foreground">Aggregation engine</p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Analysis</CardTitle>
            <Shield className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">AI-Powered</div>
            <p className="text-xs text-muted-foreground">Behavioral insights</p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Activity Tracking</CardTitle>
            <Activity className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">Timeline</div>
            <p className="text-xs text-muted-foreground">Chronological mapping</p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle>Capabilities</CardTitle>
          <CardDescription>What DigitalSoulLite can discover</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Badge variant="secondary">Email Discovery</Badge>
            <Badge variant="secondary">Phone Lookup</Badge>
            <Badge variant="secondary">Social Media Profiling</Badge>
            <Badge variant="secondary">Breach Detection</Badge>
            <Badge variant="secondary">WHOIS Data</Badge>
            <Badge variant="secondary">DNS Records</Badge>
            <Badge variant="secondary">EXIF Metadata</Badge>
            <Badge variant="secondary">Web Archives</Badge>
            <Badge variant="secondary">Network Analysis</Badge>
            <Badge variant="secondary">Behavioral Patterns</Badge>
            <Badge variant="secondary">Risk Assessment</Badge>
            <Badge variant="secondary">AI Narrative Generation</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Index;
