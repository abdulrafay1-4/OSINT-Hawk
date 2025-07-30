# OSINT Hawk 🦅

A comprehensive Open Source Intelligence (OSINT) platform for cybersecurity professionals, researchers, and analysts. OSINT Hawk provides powerful investigation capabilities across multiple data sources with a modern, user-friendly interface.

## 🚀 Features

### Investigation Types
- **👤 Username Investigation** - Search across multiple platforms for social media presence
- **📧 Email Analysis** - Pattern analysis, domain reputation, and security assessment (free alternatives to paid services)
- **🌐 Domain Intelligence** - WHOIS data, DNS records, and security reputation
- **🌍 IP Address Analysis** - Geolocation, threat intelligence, and abuse reports
- **📁 File Analysis** - Hash-based threat detection and malware analysis

### Platform Capabilities
- **Real-time Results** - Instant investigation results with comprehensive reporting
- **Modern UI** - Clean, responsive interface with dark/light mode support
- **Export Functions** - Download results in JSON, CSV, or PDF formats
- **Rate Limiting** - Built-in protection against API abuse
- **Security First** - Input validation, CORS protection, and secure headers

## 🛠️ Technology Stack

### Backend
- **Node.js** with Express.js framework
- **Helmet** for security headers
- **CORS** for cross-origin requests
- **Rate limiting** for API protection
- **Winston** for structured logging

### Frontend
- **React.js** with modern hooks
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **Responsive design** for all devices

### External APIs
- **VirusTotal** - File and URL analysis
- **AbuseIPDB** - IP reputation and abuse reports
- **IPinfo** - IP geolocation and ISP data
- **GitHub API** - Code repository searches (optional)

## 📋 Prerequisites

- Node.js 16.0.0 or higher
- npm or yarn package manager
- API keys for external services (see Configuration section)

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/abdulrafay1-4/osint-hawk.git
   cd osint-hawk
   ```

2. **Install backend dependencies**
   ```bash
   cd backend
   npm install
   ```

3. **Install frontend dependencies**
   ```bash
   cd frontend
   npm install
   ```

4. **Configure environment variables**
   ```bash
   cd ..
   cp .env.example .env
   ```
   Edit `.env` with your actual API keys (see Configuration section)

## ⚙️ Configuration

### Required API Keys

1. **VirusTotal API Key**
   - Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Get your free API key from the API section

2. **AbuseIPDB API Key**
   - Register at [AbuseIPDB](https://www.abuseipdb.com/register)
   - Generate API key in your account settings

3. **IPinfo API Token**
   - Sign up at [IPinfo](https://ipinfo.io/signup)
   - Get your access token from the dashboard

4. **GitHub API Token** (Optional)
   - Go to GitHub Settings > Developer settings > Personal access tokens
   - Generate token with public repository read access

### Environment File (.env)
```env
# Server Configuration
PORT=3001
NODE_ENV=development

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
IPINFO_API_TOKEN=your_ipinfo_api_token_here
GITHUB_API_TOKEN=your_github_api_token_here

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Security
CORS_ORIGIN=http://localhost:3000
```

## 🚀 Running the Application

### Development Mode

1. **Start the backend server**
   ```bash
   cd backend
   npm install
   npm start
   ```

4. **Access the Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:3001

## API Configuration

Add your API keys to `backend/.env`:

```env
# Security APIs
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Data APIs  
HAVEIBEENPWNED_API_KEY=your_hibp_key
IPINFO_TOKEN=your_ipinfo_token
GITHUB_TOKEN=your_github_token

# Server Configuration
PORT=3001
NODE_ENV=development
```

## API Endpoints

### Intelligence Endpoints
- `POST /osint/username` - Username investigation
- `POST /osint/email` - Email analysis
- `POST /osint/domain` - Domain research
- `POST /osint/ip` - IP address intelligence
- `POST /osint/file` - File analysis (multipart upload)

### System Endpoints
- `GET /health` - System health check
- `GET /` - API documentation

## Usage Examples

### Username Investigation
```javascript
// Find social media presence
const response = await fetch('/osint/username', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'johndoe' })
});
```

### Email Analysis
```javascript
// Check for data breaches
const response = await fetch('/osint/email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'user@example.com' })
});
```

### File Analysis
```javascript
// Upload and analyze file
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const response = await fetch('/osint/file', {
  method: 'POST',
  body: formData
});
```

## Security Features

- **Rate Limiting**: Prevents API abuse
- **Input Validation**: Comprehensive data sanitization
- **CORS Protection**: Configurable cross-origin policies
- **Helmet Security**: Standard security headers
- **Error Handling**: Secure error responses
- **Logging**: Structured logging with Winston

## Technology Stack

### Backend
- **Node.js** with Express.js framework
- **External APIs**: VirusTotal, HaveIBeenPwned, AbuseIPDB, IPinfo
- **Security**: Helmet, CORS, rate limiting, Joi validation
- **Logging**: Winston with file rotation
- **File Handling**: Multer with security checks

### Frontend
- **React.js** with modern hooks
- **Tailwind CSS** for responsive design
- **Axios** for API communication
- **Export Utilities** for data formats

## Development

### Project Structure
```
osint-hawk/
├── backend/
│   ├── routes/          # API route handlers
│   ├── services/        # Business logic
│   ├── utils/           # Helper utilities
│   └── index.js         # Main server file
├── frontend/
│   ├── src/
│   │   ├── components/  # React components
│   │   └── utils/       # Frontend utilities
│   └── public/          # Static assets
└── README.md
```

### Adding New Investigation Types

1. **Backend**: Create route in `routes/` and service in `services/`
2. **Frontend**: Add option to `ScanForm` component
3. **Update**: API documentation and validation schemas

## Legal and Ethical Use

⚠️ **Important**: This tool is designed for legitimate security research, digital forensics, and authorized investigations only.

### Guidelines
- Obtain proper authorization before investigating
- Respect privacy laws and regulations
- Follow platform terms of service
- Use responsibly and ethically
- Report findings through appropriate channels

### Disclaimer
Users are responsible for ensuring their use complies with applicable laws and regulations. The developers assume no liability for misuse.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request
5. Follow coding standards and security practices

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Follow security disclosure guidelines
- Provide detailed reproduction steps

---

**OSINT Hawk** - Empowering security professionals with comprehensive intelligence gathering capabilities. Hawk - Full-Stack Open-Source Intelligence Tool

A comprehensive OSINT (Open-Source Intelligence) tool built with Node.js (Express) backend and React.js frontend for automated intelligence gathering from public data sources.

## 🚀 Features

- **Username Investigation**: Check username availability across multiple platforms (GitHub, Reddit, Twitter)
- **Email Intelligence**: Breach detection via HaveIBeenPwned API and mention searches
- **Domain Analysis**: WHOIS lookup, DNS records, subdomain discovery
- **IP Address Investigation**: GeoIP lookup, threat intelligence, VPN/proxy detection
- **File Analysis**: Hash generation and VirusTotal scanning
- **Modern Dashboard**: React.js frontend with dark mode and responsive design
- **Export Capabilities**: Results export in JSON and HTML formats

## 🛠️ Tech Stack

### Backend
- Node.js with Express.js
- REST API architecture
- MongoDB (optional for logging)
- External API integrations (HaveIBeenPwned, VirusTotal, etc.)

### Frontend
- React.js
- Tailwind CSS for styling
- Axios for API communication
- React Toastify for notifications

## 📁 Project Structure

```
osint-hawk/
├── backend/
│   ├── routes/           # API routes per OSINT type
│   ├── services/         # Data fetching and processing logic
│   ├── utils/           # Helper functions
│   ├── config/          # Configuration and API keys
│   └── index.js         # Main server file
├── frontend/
│   ├── src/
│   │   ├── components/  # React components
│   │   └── App.jsx      # Main app component
│   └── public/
├── reports/             # Generated scan reports
├── .env                 # Environment variables
└── README.md
```

## 🏃‍♂️ Getting Started

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Installation

1. Clone the repository
2. Install backend dependencies:
   ```bash
   cd backend
   npm install
   ```

3. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Add your API keys
   ```

5. Start the backend server:
   ```bash
   cd backend
   npm start
   ```

6. Start the frontend development server:
   ```bash
   cd frontend
   npm start
   ```

## 🔧 API Endpoints

- `GET /osint/username?value=<username>` - Username investigation
- `GET /osint/email?value=<email>` - Email intelligence
- `GET /osint/domain?value=<domain>` - Domain analysis
- `GET /osint/ip?value=<ip>` - IP address investigation
- `POST /osint/file` - File analysis (upload)

## 🔐 Security Features

- Input validation and sanitization
- Rate limiting per IP/user
- API key protection
- Secure file upload handling
- CORS configuration

## 📊 Risk Levels

- 🟢 **Green**: Safe/No threats detected
- 🟡 **Yellow**: Moderate risk/warnings
- 🔴 **Red**: High risk/threats detected

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and legitimate security research purposes only. Users are responsible for ensuring their usage complies with applicable laws and terms of service.
