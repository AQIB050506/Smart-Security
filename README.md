# Next-Gen Smart Security System

A comprehensive security system with AI threat detection, link scanning, and blockchain evidence storage. This system allows users to anonymously report security issues while providing advanced threat analysis and tamper-proof evidence storage.

## 🚀 Features

### Core Features
- **Anonymous Reporting**: Submit security reports without revealing personal information
- **AI Threat Detection**: 
  - Text analysis using DistilBERT for spam, scam, harassment detection
  - Image analysis for content moderation
- **Link Scanner**: Real-time URL scanning against VirusTotal and PhishTank databases
- **Blockchain Evidence Storage**: Tamper-proof storage using Polygon testnet
- **JWT Authentication**: Secure user authentication with optional anonymous access

### Technical Stack
- **Backend**: FastAPI (Python) with PostgreSQL database
- **Frontend**: Flutter mobile application
- **AI/ML**: Transformers library with pre-trained models
- **Blockchain**: Polygon testnet integration
- **Containerization**: Docker with docker-compose

## 📋 Prerequisites

Before running the application, ensure you have:

- Docker and Docker Compose installed
- Flutter SDK (for mobile app development)
- API keys for external services (optional):
  - VirusTotal API key
  - PhishTank API key
  - Polygon RPC URL (Alchemy or Infura)
  - Private key for blockchain transactions

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cybersecurity-guard
```

### 2. Backend Setup

#### Using Docker (Recommended)

1. **Configure Environment Variables**
   ```bash
   cp backend/env.example backend/.env
   ```
   
   Edit `backend/.env` with your configuration:
   ```env
   # Database (default values work with docker-compose)
   DATABASE_URL=postgresql://security_user:security_password@postgres:5432/security_db
   
   # JWT (change in production)
   SECRET_KEY=your-secret-key-here-change-in-production
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   
   # Blockchain (optional - will use simulation if not configured)
   POLYGON_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your-api-key
   PRIVATE_KEY=your-private-key-for-blockchain-transactions
   CONTRACT_ADDRESS=your-smart-contract-address
   
   # External APIs (optional - will skip checks if not configured)
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   PHISHTANK_API_KEY=your-phishtank-api-key
   
   # File Storage
   UPLOAD_DIR=./uploads
   MAX_FILE_SIZE=10485760
   ```

2. **Start the Services**
   ```bash
   docker-compose up -d
   ```

   This will start:
   - PostgreSQL database on port 5432
   - FastAPI backend on port 8000
   - Redis cache on port 6379

3. **Verify Backend is Running**
   ```bash
   curl http://localhost:8000/health
   ```

#### Manual Setup (Alternative)

1. **Install Python Dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Set up PostgreSQL Database**
   ```bash
   # Create database
   createdb security_db
   
   # Create user
   psql -c "CREATE USER security_user WITH PASSWORD 'security_password';"
   psql -c "GRANT ALL PRIVILEGES ON DATABASE security_db TO security_user;"
   ```

3. **Run the Backend**
   ```bash
   cd backend
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### 3. Flutter App Setup

1. **Install Flutter Dependencies**
   ```bash
   cd flutter_app
   flutter pub get
   ```

2. **Configure API Endpoint**
   
   Edit `lib/services/api_service.dart` and update the base URL if needed:
   ```dart
   static const String baseUrl = 'http://localhost:8000';  // Change if backend is on different host
   ```

3. **Run the Flutter App**
   ```bash
   # For Android
   flutter run
   
   # For iOS (macOS only)
   flutter run -d ios
   
   # For web
   flutter run -d web
   ```

## 🔧 Configuration

### API Keys Setup

#### VirusTotal API
1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from the account settings
3. Add it to your `.env` file

#### PhishTank API
1. Sign up at [PhishTank](https://www.phishtank.com/)
2. Get your API key from the account settings
3. Add it to your `.env` file

#### Polygon Testnet
1. Get a Polygon Mumbai RPC URL from [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/)
2. Create a wallet and get the private key
3. Add both to your `.env` file

### Database Configuration

The application uses PostgreSQL with the following default configuration:
- Database: `security_db`
- User: `security_user`
- Password: `security_password`
- Host: `localhost` (or `postgres` in Docker)
- Port: `5432`

## 📱 Usage

### Mobile App

1. **Launch the App**: Open the Flutter app on your device
2. **Authentication Options**:
   - **Sign Up**: Create an account with email and password
   - **Sign In**: Login with existing credentials
   - **Anonymous**: Continue without registration (reports are still tracked with hashed ID)

3. **Create Reports**:
   - Tap the "+" button to create a new report
   - Add text description, suspicious links, or images
   - Submit the report for AI analysis

4. **View Reports**:
   - Navigate to the "Reports" tab to see your submitted reports
   - View classification results and blockchain verification status
   - Tap on reports for detailed information

### API Endpoints

#### Authentication
- `POST /auth/signup` - Register new user
- `POST /auth/login` - Login user
- `POST /auth/anonymous` - Create anonymous user
- `GET /auth/me` - Get current user info

#### Reports
- `POST /reports/` - Submit new report
- `GET /reports/{id}` - Get specific report
- `GET /reports/` - Get paginated reports list
- `POST /reports/scan-link` - Scan URL without creating report
- `POST /reports/analyze-text` - Analyze text without creating report
- `GET /reports/{id}/verify` - Verify report blockchain evidence

## 🔒 Security Features

### AI Threat Detection
- **Text Analysis**: Uses DistilBERT for sentiment analysis and keyword-based detection
- **Image Analysis**: Basic image validation and size checks
- **Classification**: Categorizes content as safe, spam, scam, or harassment

### Link Scanning
- **VirusTotal Integration**: Scans URLs against multiple antivirus engines
- **PhishTank Integration**: Checks URLs against phishing database
- **Real-time Analysis**: Immediate threat assessment before report submission

### Blockchain Evidence Storage
- **Tamper-proof Storage**: SHA256 hashes stored on Polygon testnet
- **Verification**: Users can verify report integrity using transaction hashes
- **Transparency**: All evidence is publicly verifiable on the blockchain

### Privacy Protection
- **Anonymous Reporting**: Users can report without revealing identity
- **Hashed User IDs**: Personal identifiers are hashed for privacy
- **Optional Email**: Email is optional for anonymous users

## 🐳 Docker Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Access database
docker-compose exec postgres psql -U security_user -d security_db

# Access backend container
docker-compose exec backend bash
```

## 🧪 Testing

### Backend Testing
```bash
cd backend
python -m pytest tests/ -v
```

### Flutter Testing
```bash
cd flutter_app
flutter test
```

## 📊 Monitoring

### Health Checks
- Backend: `GET /health`
- Database: Automatic health checks in docker-compose
- Blockchain: Connection status in health endpoint

### Logs
- Backend logs: `docker-compose logs backend`
- Database logs: `docker-compose logs postgres`
- Application logs: Available in container stdout

## 🚀 Deployment

### Production Considerations

1. **Environment Variables**: Use secure secret management
2. **Database**: Use managed PostgreSQL service
3. **API Keys**: Rotate keys regularly
4. **SSL/TLS**: Enable HTTPS for all communications
5. **Rate Limiting**: Implement API rate limiting
6. **Monitoring**: Set up application monitoring and alerting

### Scaling
- Use load balancers for multiple backend instances
- Implement Redis for session management
- Use CDN for static file serving
- Consider microservices architecture for large deployments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API documentation at `http://localhost:8000/docs`

## 🔮 Future Enhancements

- [ ] Real-time notifications
- [ ] Advanced image analysis with CLIP
- [ ] Machine learning model training pipeline
- [ ] Multi-language support
- [ ] Web dashboard for administrators
- [ ] Integration with more threat intelligence sources
- [ ] Smart contract for automated report processing
- [ ] Mobile push notifications
- [ ] Offline mode support
- [ ] Advanced reporting analytics

