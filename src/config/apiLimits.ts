export interface ApiConfig {
  name: string;
  enabled: boolean;
  dailyLimit: number;
  description: string;
}

export const API_CONFIGS: Record<string, ApiConfig> = {
  'osint-search': {
    name: 'OSINT Search',
    enabled: true,
    dailyLimit: 100,
    description: 'Main OSINT search function'
  },
  'breach-check': {
    name: 'Breach Check',
    enabled: true,
    dailyLimit: 25,
    description: 'Check for data breaches'
  },
  'dns-whois-lookup': {
    name: 'DNS/WHOIS Lookup',
    enabled: true,
    dailyLimit: 50,
    description: 'DNS and WHOIS information'
  },
  'wayback-lookup': {
    name: 'Wayback Machine',
    enabled: true,
    dailyLimit: 30,
    description: 'Historical website data'
  },
  'cert-transparency': {
    name: 'Certificate Transparency',
    enabled: true,
    dailyLimit: 50,
    description: 'SSL certificate logs'
  },
  'hunter-io': {
    name: 'Hunter.io',
    enabled: false,
    dailyLimit: 50,
    description: 'Email finder and verification'
  },
  'shodan': {
    name: 'Shodan',
    enabled: false,
    dailyLimit: 100,
    description: 'Internet-connected device search'
  },
  'pipl': {
    name: 'Pipl',
    enabled: false,
    dailyLimit: 20,
    description: 'Deep people search'
  },
  'social-searcher': {
    name: 'Social-Searcher',
    enabled: false,
    dailyLimit: 100,
    description: 'Social media monitoring'
  }
};
