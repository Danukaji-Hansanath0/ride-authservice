#!/bin/bash

# Auth Service Standalone Start Script
# This script helps you quickly start the auth-service for testing

set -e

echo "=========================================="
echo "Auth Service - Standalone Start Script"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from template..."
    cat > .env << 'EOF'
# VPS Configuration
VPS_IP_ADDRESS=localhost
EOF
    echo "✅ Created .env file with default values"
    echo ""
fi

# Check if running on VPS or local
echo "📍 Current configuration:"
source .env
echo "   VPS_IP_ADDRESS: ${VPS_IP_ADDRESS:-localhost}"
echo ""

# Ask if user wants to update VPS IP
read -p "Do you want to update the VPS IP address? (y/N): " update_ip
if [[ $update_ip =~ ^[Yy]$ ]]; then
    read -p "Enter your VPS IP address: " vps_ip
    sed -i "s/VPS_IP_ADDRESS=.*/VPS_IP_ADDRESS=$vps_ip/" .env
    echo "✅ Updated VPS_IP_ADDRESS to: $vps_ip"
    echo ""
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "🐳 Docker is running"
echo ""

# Check if ports are available
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        echo "⚠️  Port $1 is already in use"
        return 1
    fi
    return 0
}

echo "🔍 Checking ports..."
ports_available=true

if ! check_port 8081; then
    ports_available=false
fi

if ! check_port 5672; then
    ports_available=false
fi

if ! check_port 15672; then
    ports_available=false
fi

if [ "$ports_available" = false ]; then
    echo ""
    read -p "Some ports are in use. Continue anyway? (y/N): " continue_anyway
    if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
        echo "Exiting..."
        exit 1
    fi
fi

echo ""
echo "🚀 Starting auth-service..."
echo ""

# Ask for run mode
echo "Select run mode:"
echo "  1) Foreground (view logs in terminal)"
echo "  2) Background (detached mode)"
read -p "Enter choice (1 or 2): " run_mode

case $run_mode in
    1)
        echo ""
        echo "Starting in foreground mode..."
        echo "Press Ctrl+C to stop"
        echo ""
        docker-compose up --build
        ;;
    2)
        echo ""
        echo "Starting in background mode..."
        docker-compose up --build -d

        echo ""
        echo "⏳ Waiting for services to start..."
        sleep 5

        echo ""
        echo "📊 Service Status:"
        docker-compose ps

        echo ""
        echo "✅ Auth Service started successfully!"
        echo ""
        echo "📍 Access Points:"
        echo "   • Auth Service API: http://localhost:8081"
        echo "   • Swagger UI: http://localhost:8081/swagger-ui.html"
        echo "   • RabbitMQ Management: http://localhost:15672 (guest/guest)"
        echo ""
        echo "📝 Useful Commands:"
        echo "   • View logs: docker-compose logs -f auth-service"
        echo "   • Stop services: docker-compose down"
        echo "   • Restart: docker-compose restart"
        echo ""
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

