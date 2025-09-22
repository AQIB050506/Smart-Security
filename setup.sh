#!/bin/bash

# Next-Gen Smart Security System Setup Script
# This script sets up the development environment

set -e

echo "🚀 Setting up Next-Gen Smart Security System..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Flutter is installed
if ! command -v flutter &> /dev/null; then
    echo "⚠️  Flutter is not installed. Please install Flutter for mobile app development."
    echo "   Visit: https://flutter.dev/docs/get-started/install"
fi

echo "✅ Prerequisites check completed"

# Create environment file if it doesn't exist
if [ ! -f backend/.env ]; then
    echo "📝 Creating environment configuration..."
    cp backend/env.example backend/.env
    echo "✅ Environment file created at backend/.env"
    echo "⚠️  Please edit backend/.env with your API keys and configuration"
else
    echo "✅ Environment file already exists"
fi

# Create uploads directory
echo "📁 Creating uploads directory..."
mkdir -p backend/uploads
echo "✅ Uploads directory created"

# Start Docker services
echo "🐳 Starting Docker services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check if backend is healthy
echo "🔍 Checking backend health..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if curl -f http://localhost:8000/health &> /dev/null; then
        echo "✅ Backend is healthy"
        break
    else
        echo "⏳ Attempt $attempt/$max_attempts - Backend not ready yet..."
        sleep 2
        ((attempt++))
    fi
done

if [ $attempt -gt $max_attempts ]; then
    echo "❌ Backend failed to start properly"
    echo "📋 Check logs with: docker-compose logs backend"
    exit 1
fi

# Setup Flutter dependencies
if command -v flutter &> /dev/null; then
    echo "📱 Setting up Flutter dependencies..."
    cd flutter_app
    flutter pub get
    cd ..
    echo "✅ Flutter dependencies installed"
else
    echo "⚠️  Skipping Flutter setup (Flutter not installed)"
fi

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit backend/.env with your API keys (optional)"
echo "2. Backend API is available at: http://localhost:8000"
echo "3. API documentation at: http://localhost:8000/docs"
echo "4. Run Flutter app: cd flutter_app && flutter run"
echo ""
echo "🔧 Useful commands:"
echo "• View logs: docker-compose logs -f"
echo "• Stop services: docker-compose down"
echo "• Restart services: docker-compose restart"
echo "• Access database: docker-compose exec postgres psql -U security_user -d security_db"
echo ""
echo "📚 For more information, see README.md"

