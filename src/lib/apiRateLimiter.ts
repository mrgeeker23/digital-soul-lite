import { API_CONFIGS, type ApiConfig } from '@/config/apiLimits';

interface UsageRecord {
  count: number;
  date: string;
}

const STORAGE_KEY = 'osint_api_usage';

class ApiRateLimiter {
  private getToday(): string {
    return new Date().toISOString().split('T')[0];
  }

  private getUsageData(): Record<string, UsageRecord> {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return {};
    
    try {
      return JSON.parse(stored);
    } catch {
      return {};
    }
  }

  private saveUsageData(data: Record<string, UsageRecord>): void {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  private cleanupOldData(data: Record<string, UsageRecord>): Record<string, UsageRecord> {
    const today = this.getToday();
    const cleaned: Record<string, UsageRecord> = {};
    
    for (const [key, value] of Object.entries(data)) {
      if (value.date === today) {
        cleaned[key] = value;
      }
    }
    
    return cleaned;
  }

  canCallApi(apiName: string): { allowed: boolean; reason?: string; usage?: { current: number; limit: number } } {
    const config = API_CONFIGS[apiName];
    
    if (!config) {
      return { allowed: false, reason: `Unknown API: ${apiName}` };
    }

    if (!config.enabled) {
      return { allowed: false, reason: `${config.name} is currently disabled` };
    }

    const today = this.getToday();
    let usageData = this.getUsageData();
    usageData = this.cleanupOldData(usageData);

    const currentUsage = usageData[apiName];
    const count = currentUsage?.date === today ? currentUsage.count : 0;

    if (count >= config.dailyLimit) {
      return {
        allowed: false,
        reason: `Daily limit reached for ${config.name} (${count}/${config.dailyLimit})`,
        usage: { current: count, limit: config.dailyLimit }
      };
    }

    return {
      allowed: true,
      usage: { current: count, limit: config.dailyLimit }
    };
  }

  incrementUsage(apiName: string): void {
    const today = this.getToday();
    let usageData = this.getUsageData();
    usageData = this.cleanupOldData(usageData);

    const currentUsage = usageData[apiName];
    
    if (currentUsage?.date === today) {
      currentUsage.count++;
    } else {
      usageData[apiName] = { count: 1, date: today };
    }

    this.saveUsageData(usageData);
  }

  getUsageStats(apiName: string): { current: number; limit: number; percentage: number } {
    const config = API_CONFIGS[apiName];
    if (!config) {
      return { current: 0, limit: 0, percentage: 0 };
    }

    const today = this.getToday();
    const usageData = this.getUsageData();
    const currentUsage = usageData[apiName];
    const count = currentUsage?.date === today ? currentUsage.count : 0;

    return {
      current: count,
      limit: config.dailyLimit,
      percentage: (count / config.dailyLimit) * 100
    };
  }

  getAllUsageStats(): Array<{ apiName: string; config: ApiConfig; stats: ReturnType<typeof this.getUsageStats> }> {
    return Object.entries(API_CONFIGS).map(([apiName, config]) => ({
      apiName,
      config,
      stats: this.getUsageStats(apiName)
    }));
  }

  resetUsage(apiName?: string): void {
    if (apiName) {
      const usageData = this.getUsageData();
      delete usageData[apiName];
      this.saveUsageData(usageData);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }
}

export const apiRateLimiter = new ApiRateLimiter();
