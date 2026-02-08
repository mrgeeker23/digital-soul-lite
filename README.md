# DigitalSoul Lite
DigitalSoul Lite demonstrates the practical implementation of ethical OSINT principles through a functional multi-source intelligence aggregation platform. By integrating breach databases, certificate transparency logs, DNS security records, social media enumeration, and phone intelligence APIs into a unified interface, the tool provides users with actionable insights into their digital exposure while maintaining strict privacy boundaries. The architecture successfully balances accessibility—requiring no technical expertise to operate—with technical sophistication through edge function-based API security, rate limiting mechanisms, and real-time risk classification algorithms.

This proof-of-concept validates the feasibility of democratizing digital footprint analysis for individual privacy awareness and security research. The platform addresses a critical gap in personal cybersecurity tooling: most OSINT capabilities remain fragmented across commercial platforms or require technical expertise to access. DigitalSoul Lite consolidates this intelligence into an ethical, transparent, and user-friendly application that respects data protection regulations while empowering users to understand their publicly accessible information footprint.

The project reinforced fundamental principles in secure API integration, privacy-by-design architecture, and responsible disclosure of security intelligence. Through iterative development, I gained practical experience in handling rate-limited external services, designing intuitive security visualizations, and implementing compliance frameworks that align with international privacy standards including GDPR, APAC regional requirements, and NIST cybersecurity guidelines.

## Features

- **Social Media Intelligence** - Scan 24+ platforms for username presence
- **Data Breach Detection** - Check exposure in known data breaches
- **DNS/WHOIS Lookup** - Domain infrastructure analysis
- **Certificate Transparency** - SSL/TLS certificate discovery
- **Web Archive Analysis** - Historical website snapshots via Wayback Machine
- **Risk Scoring** - AI-powered threat assessment

## Tech Stack

- React + TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- Supabase Edge Functions

## Getting Started

```sh
# Install dependencies
npm install

# Start development server
npm run dev
```

## API Rate Limits

| API | Daily Limit |
|-----|-------------|
| OSINT Search | 100 |
| Breach Check | 25 |
| DNS/WHOIS | 50 |
| Wayback Machine | 30 |
| Cert Transparency | 50 |

## Author

**abdulabdul technologies**

---

*Built for cybersecurity research and digital footprint analysis*
