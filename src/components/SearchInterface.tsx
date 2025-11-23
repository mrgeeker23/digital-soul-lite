import { useState } from "react";
import { Search, User, Mail, Phone, AlertTriangle, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { apiRateLimiter } from "@/lib/apiRateLimiter";

interface SearchInterfaceProps {
  onResults?: (results: any) => void;
}

export function SearchInterface({ onResults }: SearchInterfaceProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchType, setSearchType] = useState<"username" | "email" | "phone">("username");
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      toast({
        title: "Error",
        description: "Please enter a search query",
        variant: "destructive",
      });
      return;
    }

    // Check rate limits before making API call
    const apiCheck = apiRateLimiter.canCallApi('osint-search');
    if (!apiCheck.allowed) {
      toast({
        title: "Rate Limit Reached",
        description: apiCheck.reason || "You've reached the daily limit for this API",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);
    console.log(`Searching ${searchType}:`, searchQuery);

    try {
      const { data, error } = await supabase.functions.invoke('osint-search', {
        body: { query: searchQuery, type: searchType }
      });

      if (error) throw error;

      // Increment usage counter after successful call
      apiRateLimiter.incrementUsage('osint-search');
      
      // Increment usage for each API that was actually called
      if (data.apisUsed && Array.isArray(data.apisUsed)) {
        data.apisUsed.forEach((apiName: string) => {
          apiRateLimiter.incrementUsage(apiName);
        });
      }

      console.log("Search results:", data);
      
      toast({
        title: "Search Complete",
        description: `Found data for ${searchQuery}`,
      });

      if (onResults) {
        onResults(data);
      }
    } catch (error) {
      console.error("Search error:", error);
      toast({
        title: "Search Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5 text-primary" />
            Search Intelligence Interface
          </CardTitle>
          <CardDescription>
            Begin your digital footprint analysis by entering a username, email, or phone number
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={searchType} onValueChange={(v) => setSearchType(v as typeof searchType)}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="username" className="flex items-center gap-2">
                <User className="h-4 w-4" />
                Username
              </TabsTrigger>
              <TabsTrigger value="email" className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Email
              </TabsTrigger>
              <TabsTrigger value="phone" className="flex items-center gap-2">
                <Phone className="h-4 w-4" />
                Phone
              </TabsTrigger>
            </TabsList>

            <TabsContent value="username" className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Enter username (e.g., @johndoe)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1"
                />
                <Button 
                  onClick={handleSearch} 
                  disabled={isLoading}
                  className="bg-primary hover:bg-primary/90"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4 mr-2" />
                      Search
                    </>
                  )}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="email" className="space-y-4">
              <div className="flex gap-2">
                <Input
                  type="email"
                  placeholder="Enter email address"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1"
                />
                <Button 
                  onClick={handleSearch} 
                  disabled={isLoading}
                  className="bg-primary hover:bg-primary/90"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4 mr-2" />
                      Search
                    </>
                  )}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="phone" className="space-y-4">
              <div className="flex gap-2">
                <Input
                  type="tel"
                  placeholder="Enter phone number"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1"
                />
                <Button 
                  onClick={handleSearch} 
                  disabled={isLoading}
                  className="bg-primary hover:bg-primary/90"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4 mr-2" />
                      Search
                    </>
                  )}
                </Button>
              </div>
            </TabsContent>
          </Tabs>

          <Alert className="bg-muted border-border">
            <AlertTriangle className="h-4 w-4 text-warning" />
            <AlertDescription className="text-sm text-muted-foreground">
              <strong>Ethical Use Only:</strong> This tool aggregates publicly available data for
              educational and security research purposes. Do not use for harassment, stalking, or
              illegal activities. All searches are logged.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
}
