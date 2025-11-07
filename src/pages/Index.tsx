import { useState } from "react";
import { SearchInterface } from "@/components/SearchInterface";
import { ResultsDisplay } from "@/components/ResultsDisplay";
import { ApiUsageMonitor } from "@/components/ApiUsageMonitor";
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

      <ApiUsageMonitor />

      {searchResults && <ResultsDisplay results={searchResults} />}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Data Sources</CardTitle>
            <Database className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24+</div>
            <p className="text-xs text-muted-foreground">Platforms checked</p>
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
          <CardDescription>What DigitalSoulLite discovers across the web</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-primary">Social Media Intelligence (24+ Platforms)</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">GitHub</Badge>
              <Badge variant="secondary">Reddit</Badge>
              <Badge variant="secondary">Instagram</Badge>
              <Badge variant="secondary">Twitter/X</Badge>
              <Badge variant="secondary">TikTok</Badge>
              <Badge variant="secondary">YouTube</Badge>
              <Badge variant="secondary">LinkedIn</Badge>
              <Badge variant="secondary">Twitch</Badge>
              <Badge variant="secondary">Medium</Badge>
              <Badge variant="secondary">Dev.to</Badge>
              <Badge variant="secondary">Pinterest</Badge>
              <Badge variant="secondary">+ 13 more platforms</Badge>
            </div>
          </div>
          
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-primary">Security & Infrastructure</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Data Breach Detection</Badge>
              <Badge variant="secondary">WHOIS Lookup</Badge>
              <Badge variant="secondary">DNS Records</Badge>
              <Badge variant="secondary">Certificate Transparency</Badge>
              <Badge variant="secondary">Subdomain Discovery</Badge>
              <Badge variant="secondary">Web Archives</Badge>
            </div>
          </div>
          
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-primary">Data Extraction</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Profile Metadata</Badge>
              <Badge variant="secondary">Account Creation Dates</Badge>
              <Badge variant="secondary">Follower/Following Counts</Badge>
              <Badge variant="secondary">Location & Company Info</Badge>
              <Badge variant="secondary">Bio & Descriptions</Badge>
              <Badge variant="secondary">Activity Patterns</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Index;
