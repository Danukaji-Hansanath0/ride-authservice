#!/bin/bash

# Auth Service VPS Startup Script
# This script helps you start auth-service on a VPS with proper IP configuration

set -e

echo "=================================="
echo "Auth Service - VPS Startup"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${NC}ℹ $1${NC}"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi
print_success "Docker is installed"

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi
print_success "Docker Compose is installed"

# Detect VPS IP address
echo ""
echo "Detecting IP addresses..."
echo ""

# Get all IP addresses
HOSTNAME=$(hostname)
PRIVATE_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "Unable to detect")

echo "Hostname: $HOSTNAME"
echo "Private IP: $PRIVATE_IP"
echo "Public IP: $PUBLIC_IP"
echo ""

# Ask user which IP to use
echo "Which IP address should RD_AUTH_SERVER_HOST use?"
echo "1) Public IP ($PUBLIC_IP) - Use this if accessing from external networks"
echo "2) Private IP ($PRIVATE_IP) - Use this for internal network only"
echo "3) localhost - Use this for local testing only"
echo "4) Custom IP - Enter your own"
echo ""

read -p "Select option [1-4] (default: 1): " ip_choice
ip_choice=${ip_choice:-1}

case $ip_choice in
    1)
        VPS_IP=$PUBLIC_IP
        print_info "Using Public IP: $VPS_IP"
        ;;
    2)
        VPS_IP=$PRIVATE_IP
        print_info "Using Private IP: $VPS_IP"
        ;;
    3)
        VPS_IP="localhost"
        print_info "Using localhost"
        ;;
    4)
        read -p "Enter custom IP address: " VPS_IP
        print_info "Using custom IP: $VPS_IP"
        ;;
    *)
        VPS_IP=$PUBLIC_IP
        print_warning "Invalid option. Using Public IP: $VPS_IP"
        ;;
esac

# Update or create .env file
echo ""
echo "Updating .env file..."
cat > .env << EOF
# VPS Configuration
VPS_IP_ADDRESS=$VPS_IP

# Auth Service Configuration
RD_AUTH_SERVER_PORT=8081
RD_AUTH_SERVER_HOST=$VPS_IP

# Optional: RabbitMQ Configuration (if needed)
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USERNAME=guest
RABBITMQ_PASSWORD=guest

# Optional: User Service (if available)
USER_SERVICE_URL=http://localhost:8086

# Keycloak Configuration (optional - update if needed)
RD_KEYCLOAK_SERVER_URL=https://auth.rydeflexi.com/
RD_KEYCLOAK_ADMIN_REALM=user-authentication
RD_KEYCLOAK_ADMIN_CLIENT_ID=auth-client
RD_KEYCLOAK_ADMIN_CLIENT_SECRET=61wbbZiDccvr53XUfEq0WOXvNtSdu1Sy
EOF
print_success ".env file created/updated"

# Display configuration
echo ""
echo "=================================="
echo "Configuration Summary:"
echo "=================================="
cat .env
echo "=================================="
echo ""

# Ask which mode to use
echo "Choose deployment mode:"
echo "1) Standalone (No RabbitMQ) - Recommended for VPS"
echo "2) Full stack (With RabbitMQ)"
echo ""

read -p "Select option [1-2] (default: 1): " mode_choice
mode_choice=${mode_choice:-1}

COMPOSE_FILE="docker-compose.standalone.yaml"
if [ "$mode_choice" == "2" ]; then
    COMPOSE_FILE="docker-compose.yaml"
    print_info "Using full stack mode with RabbitMQ"
else
    print_info "Using standalone mode (no RabbitMQ)"
fi

# Ask for run mode
echo ""
read -p "Run in background mode? [y/N] (default: N): " background
background=${background:-n}

# Check if port 8081 is available
if lsof -i:8081 &> /dev/null; then
    print_warning "Port 8081 is already in use!"
    read -p "Do you want to stop existing services and continue? [y/N]: " stop_existing
    if [[ $stop_existing =~ ^[Yy]$ ]]; then
        docker-compose -f $COMPOSE_FILE down
        print_success "Stopped existing services"
    else
        print_error "Cannot start service while port 8081 is in use"
        exit 1
    fi
fi

# Build and start the service
echo ""
echo "Building and starting auth-service..."
echo "This may take a few minutes on first run..."
echo ""

if [[ $background =~ ^[Yy]$ ]]; then
    docker-compose -f $COMPOSE_FILE up --build -d
    print_success "Auth service started in background mode"
    echo ""
    echo "View logs with: docker-compose -f $COMPOSE_FILE logs -f"
else
    print_info "Starting in foreground mode (Press Ctrl+C to stop)..."
    docker-compose -f $COMPOSE_FILE up --build
fi

# Display access information
echo ""
echo "=================================="
echo "Auth Service is running!"
echo "=================================="
echo ""
echo "Access the service at:"
echo "  - Local: http://localhost:8081"
echo "  - VPS IP: http://$VPS_IP:8081"
if [ "$PUBLIC_IP" != "Unable to detect" ] && [ "$VPS_IP" != "$PUBLIC_IP" ]; then
    echo "  - Public IP: http://$PUBLIC_IP:8081"
fi
echo ""
echo "Swagger UI: http://$VPS_IP:8081/swagger-ui.html"
echo "Health Check: http://$VPS_IP:8081/actuator/health"
echo ""

if [[ $background =~ ^[Yy]$ ]]; then
    echo "Service is running in background."
    echo ""
    echo "Useful commands:"
    echo "  View logs:      docker-compose -f $COMPOSE_FILE logs -f"
    echo "  Stop service:   docker-compose -f $COMPOSE_FILE stop"
    echo "  Restart:        docker-compose -f $COMPOSE_FILE restart"
    echo "  Stop & remove:  docker-compose -f $COMPOSE_FILE down"
    echo ""
fi

# Firewall reminder
if [ "$VPS_IP" != "localhost" ]; then
    echo ""
    print_warning "IMPORTANT: Make sure your firewall allows connections on port 8081"
    echo ""
    echo "For Ubuntu/Debian:"
    echo "  sudo ufw allow 8081/tcp"
    echo "  sudo ufw reload"
    echo ""
    echo "For CentOS/RHEL:"
    echo "  sudo firewall-cmd --permanent --add-port=8081/tcp"
    echo "  sudo firewall-cmd --reload"
    echo ""
fi

print_success "Setup complete!"

