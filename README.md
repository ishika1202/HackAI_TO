# 🛡️ SponsorGuard - AI-Powered Sponsor Verification

Protect your brand with AI-powered sponsor email verification. Detect scams, verify legitimacy, and save time.

![SponsorGuard](https://via.placeholder.com/800x400/1e293b/3b82f6?text=SponsorGuard)

## 🚀 Features

- **AI-Powered Analysis**: OpenAI GPT-4 analyzes email content for scam indicators
- **Domain Verification**: WHOIS lookup, age verification, reputation checks  
- **Multiple Security APIs**: Google Safe Browsing, IPQualityScore, VirusTotal integration
- **Risk Scoring**: 0-100% risk assessment with detailed explanations
- **Professional UI**: Modern dark theme with HeroUI-inspired design
- **Real-time Analysis**: Get results in seconds

## 🛠️ Tech Stack

- **Frontend**: Next.js 14, React, TypeScript, Tailwind CSS
- **Backend**: Next.js API routes (serverless)
- **AI/ML**: OpenAI GPT-4o-mini
- **Verification APIs**: 
  - WHOIS (WhoXY/WhoisXML)
  - Google Safe Browsing
  - IPQualityScore
  - VirusTotal
- **Deployment**: Vercel

## 🏃‍♂️ Quick Start

### 1. Clone & Install

\`\`\`bash
git clone <your-repo>
cd sponsor-guard
npm install
\`\`\`

### 2. Environment Setup

Create \`.env.local\`:

\`\`\`env
# Required for AI analysis
OPENAI_API_KEY=your_openai_api_key_here

# Optional but recommended for production
WHOIS_API_KEY=your_whois_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
\`\`\`

#### 🔑 Getting API Keys:

**OpenAI** (Required):
- Visit: https://platform.openai.com/api-keys
- Create account → API Keys → Create new key

**WhoisXML API** (Recommended):
- Visit: https://whoisxmlapi.com/
- Free tier: 1,000 requests/month
- Sign up → Dashboard → API Key

**Google Safe Browsing** (Recommended):
- Visit: https://developers.google.com/safe-browsing/v4/get-started
- Enable Safe Browsing API → Create credentials

**IPQualityScore** (Recommended):
- Visit: https://www.ipqualityscore.com/
- Free tier: 5,000 requests/month
- Sign up → API → Get API Key

**VirusTotal** (Optional):
- Visit: https://www.virustotal.com/gui/join-us
- Free tier: 4 requests/minute
- Sign up → Profile → API Key

### 3. Run Development Server

\`\`\`bash
npm run dev
\`\`\`

Open [http://localhost:3000](http://localhost:3000)

## 🌐 Deploy to Vercel

### One-Click Deploy

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-username/sponsor-guard)

### Manual Deploy

1. Push to GitHub
2. Connect to Vercel
3. Add environment variables
4. Deploy!

## 📝 API Documentation

### POST /api/verify

Analyze sponsor email content for scam indicators.

**Request:**
\`\`\`json
{
  "emailContent": "string"
}
\`\`\`

**Response:**
\`\`\`json
{
  "riskScore": 65,
  "status": "warning",
  "flags": [
    {
      "type": "yellow",
      "message": "AI detected: Urgency tactics"
    }
  ],
  "domainInfo": {
    "age": "2 years",
    "registrar": "GoDaddy",
    "country": "US"
  },
  "summary": "Email contains several warning signs...",
  "suggestedAction": "Exercise caution. Request additional verification..."
}
\`\`\`

## 🔒 Security Features

- **Email Pattern Detection**: Extracts emails and URLs automatically
- **Domain Age Analysis**: Checks how long domains have been registered
- **Content Analysis**: AI evaluates language patterns and red flags
- **URL Shortener Detection**: Flags suspicious shortened URLs
- **Crypto/Scam Keywords**: Identifies common scam terminology

## 🎨 UI Components

The app uses a professional dark theme with:
- Gradient backgrounds and accents
- Glass-morphism cards
- Smooth animations with Framer Motion
- Responsive design
- Accessibility features

## 📊 Risk Scoring Algorithm

Risk scores are calculated based on:
- AI legitimacy assessment (0-100)
- Red flag penalties (+25 each)
- Yellow flag penalties (+10 each)  
- Green flag bonuses (-5 each)

**Score Ranges:**
- 0-30%: Safe ✅
- 31-70%: Warning ⚠️
- 71-100%: Danger ❌

## 🧪 Testing

Try these sample emails:

**Legitimate:**
\`\`\`
From: partnerships@nike.com
Subject: Nike Partnership Opportunity

Hello [Name],

We're interested in collaborating with you for our new product launch...
\`\`\`

**Suspicious:**
\`\`\`
From: offers@tempmail123.com
Subject: URGENT! $10,000 Sponsorship Deal - Act Now!

Hi creator! Amazing opportunity for you! Send us your bank details to receive $10,000 immediately...
\`\`\`

## 🤝 Contributing

1. Fork the repo
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

MIT License - see LICENSE file for details.

---

Built with ❤️ for content creators who deserve better sponsor verification. 