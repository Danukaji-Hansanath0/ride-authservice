# Auth Service - Quick Start

## 🚀 Quick Start (Easiest Method)

```bash
./start.sh
```

This interactive script will guide you through:
1. Configuring your VPS IP address (if needed)
2. Checking Docker and port availability
3. Starting the services

## 🐳 Manual Docker Compose Start

### Prerequisites
Ensure you're running commands from the **parent directory** (`Ride/`), not from `auth-service/`:

```bash
# Go to parent directory
cd /path/to/Ride

# Start auth-service
cd auth-service
docker-compose up --build
```

### For Background Mode
```bash
cd auth-service
docker-compose up --build -d
```

## 🌐 Access Points

Once running, access:
- **Auth Service API**: http://localhost:8081
- **Swagger UI**: http://localhost:8081/swagger-ui.html
- **API Docs**: http://localhost:8081/v3/api-docs
- **RabbitMQ Management**: http://localhost:15672 (username: `guest`, password: `guest`)

## ⚙️ VPS Configuration

To use your VPS IP address:

1. Edit `.env` file:
```bash
nano .env
```

2. Update the VPS_IP_ADDRESS:
```env
VPS_IP_ADDRESS=your-vps-ip-address
```

3. Restart services:
```bash
docker-compose restart
```

## 📝 Common Commands

```bash
# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down

# Restart services
docker-compose restart

# Rebuild after code changes
docker-compose up --build -d

# Remove all data and restart fresh
docker-compose down -v
docker-compose up --build -d
```

## 🔍 Health Check

Test if the service is running:
```bash
curl http://localhost:8081/actuator/health
```

## 📖 Full Documentation

For detailed troubleshooting and advanced configurations, see [STANDALONE_TESTING.md](./STANDALONE_TESTING.md)

## ⚠️ Important Notes

1. **Build Context**: The Docker build requires access to the parent `pom.xml`, so the docker-compose.yaml uses `context: ..` (parent directory)
2. **Ports Required**: 8081 (auth-service), 5672 (RabbitMQ), 15672 (RabbitMQ UI)
3. **Dependencies**: Only RabbitMQ is required for standalone testing

## 🐛 Troubleshooting

### Build fails with "parent POM not found"
Make sure you're in the correct directory structure and the parent `pom.xml` exists at `../pom.xml`

### Port already in use
```bash
# Check what's using the port
lsof -i :8081

# Kill the process or change the port in docker-compose.yaml
```

### RabbitMQ connection refused
Wait 30-60 seconds for RabbitMQ to fully start, then restart auth-service:
```bash
docker-compose restart auth-service
```

