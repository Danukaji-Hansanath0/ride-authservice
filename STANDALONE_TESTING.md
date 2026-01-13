# Auth Service - Standalone Testing Guide

This guide explains how to run and test the auth-service independently using Docker Compose.

## Prerequisites

- Docker installed (version 20.10+)
- Docker Compose installed (version 2.0+)
- Ports 8081, 5672, and 15672 available

## Quick Start

### Method 1: VPS Deployment (Recommended for VPS/Cloud Servers)

For deploying on a VPS or cloud server with automatic IP detection:

```bash
cd auth-service
chmod +x start-vps.sh
./start-vps.sh
```

The script will:
- Detect your VPS public and private IP addresses
- Let you choose which IP to use for RD_AUTH_SERVER_HOST
- Configure the .env file automatically
- Choose between standalone (no RabbitMQ) or full stack mode
- Check if required ports are available
- Start the services in foreground or background mode

**This is the recommended method if you are on a VPS!**

### Method 2: Using the Original Start Script

For local development or manual configuration:

```bash
cd auth-service
./start.sh
```

The script will:
- Check if Docker is running
- Let you configure VPS IP address
- Check if required ports are available
- Start the services in foreground or background mode

### Method 3: Manual Docker Compose (Standalone - No RabbitMQ)

#### 1. Configure Environment Variables

Edit the `.env` file to set your VPS IP address:

```bash
# Create or edit .env file
nano .env
```

Add these lines:
```bash
VPS_IP_ADDRESS=your-vps-ip-address
RD_AUTH_SERVER_HOST=your-vps-ip-address
# Example: 
# VPS_IP_ADDRESS=45.123.45.67
# RD_AUTH_SERVER_HOST=45.123.45.67
```

For local testing, you can use `localhost`.

#### 2. Start the Auth Service (Standalone - No RabbitMQ)

From the `auth-service` directory, run:

```bash
# Build and start the service (without RabbitMQ)
docker-compose -f docker-compose.standalone.yaml up --build

# Or run in detached mode (background)
docker-compose -f docker-compose.standalone.yaml up --build -d
```

#### 3. Verify Service is Running

Check service status:
```bash
docker-compose -f docker-compose.standalone.yaml ps
```

You should see:
- `auth-service-standalone` - Running on port 8081

### Method 4: Manual Docker Compose (Full Stack with RabbitMQ)

If you need RabbitMQ for message queue functionality:

#### 1. Use the same .env configuration as above

#### 2. Start with RabbitMQ

```bash
# Build and start the services (with RabbitMQ)
docker-compose up --build

# Or run in detached mode (background)
docker-compose up --build -d
```

#### 3. Verify Services are Running

Check service status:
```bash
docker-compose ps
```

You should see:
- `auth-service` - Running on port 8081
- `rabbitmq` - Running on ports 5672 (AMQP) and 15672 (Management UI)

## Access the Services

### Standalone Mode (No RabbitMQ):
- **Auth Service API**: http://localhost:8081 or http://YOUR-VPS-IP:8081
- **Auth Service Swagger UI**: http://YOUR-VPS-IP:8081/swagger-ui.html
- **Auth Service API Docs**: http://YOUR-VPS-IP:8081/v3/api-docs
- **Health Check**: http://YOUR-VPS-IP:8081/actuator/health

### Full Stack Mode (With RabbitMQ):
- **Auth Service API**: http://localhost:8081 or http://YOUR-VPS-IP:8081
- **Auth Service Swagger UI**: http://YOUR-VPS-IP:8081/swagger-ui.html
- **Auth Service API Docs**: http://YOUR-VPS-IP:8081/v3/api-docs
- **Health Check**: http://YOUR-VPS-IP:8081/actuator/health

## Testing the Auth Service

### Health Check
```bash
curl http://localhost:8081/actuator/health
```

### Test Authentication Endpoints
```bash
# Example: Check if service is responding
curl -X GET http://localhost:8081/swagger-ui.html
```

Open Swagger UI in your browser to test all available endpoints:
```
http://localhost:8081/swagger-ui.html
```

## Managing the Services

### View Logs
```bash
# View all logs
docker-compose logs

# View auth-service logs only
docker-compose logs auth-service

# Follow logs in real-time
docker-compose logs -f auth-service
```

### Stop Services
```bash
# Stop services (keeps data)
docker-compose stop

# Stop and remove containers (keeps volumes)
docker-compose down

# Stop and remove everything including volumes
docker-compose down -v
```

### Restart Services
```bash
# Restart all services
docker-compose restart

# Restart only auth-service
docker-compose restart auth-service
```

### Rebuild After Code Changes
```bash
# Rebuild and restart
docker-compose up --build -d

# Force rebuild without cache
docker-compose build --no-cache
docker-compose up -d
```

## Troubleshooting

### Service Won't Start

1. Check if ports are already in use:
```bash
# Check port 8081
lsof -i :8081

# Check port 5672
lsof -i :5672
```

2. View detailed logs:
```bash
docker-compose logs auth-service
```

### RabbitMQ Connection Issues

1. Check RabbitMQ health:
```bash
docker-compose exec rabbitmq rabbitmq-diagnostics ping
```

2. Access RabbitMQ Management UI:
```
http://localhost:15672
```

3. Verify RabbitMQ is healthy:
```bash
docker-compose ps rabbitmq
```

### Can't Connect from External Clients

If running on a VPS and can't connect from external machines:

1. Update `.env` with your VPS IP:
```bash
VPS_IP_ADDRESS=your-vps-public-ip
```

2. Ensure firewall allows connections:
```bash
# On Ubuntu/Debian
sudo ufw allow 8081/tcp
sudo ufw allow 5672/tcp
sudo ufw allow 15672/tcp

# On CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --permanent --add-port=5672/tcp
sudo firewall-cmd --permanent --add-port=15672/tcp
sudo firewall-cmd --reload
```

3. Restart services:
```bash
docker-compose restart
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VPS_IP_ADDRESS` | Server IP address | `localhost` |
| `RD_AUTH_SERVER_PORT` | Auth service port | `8081` |
| `RD_AUTH_SERVER_HOST` | Auth service host | `localhost` |
| `RABBITMQ_HOST` | RabbitMQ hostname | `rabbitmq` |
| `RABBITMQ_PORT` | RabbitMQ port | `5672` |
| `RABBITMQ_USERNAME` | RabbitMQ username | `guest` |
| `RABBITMQ_PASSWORD` | RabbitMQ password | `guest` |
| `USER_SERVICE_URL` | User service URL | `http://localhost:8086` |

## Docker Commands Reference

### Container Management
```bash
# List running containers
docker-compose ps

# Access auth-service container shell
docker-compose exec auth-service sh

# Access RabbitMQ container shell
docker-compose exec rabbitmq bash

# View container resource usage
docker stats
```

### Volume Management
```bash
# List volumes
docker volume ls

# Inspect RabbitMQ volume
docker volume inspect auth-service_rabbitmq-data

# Remove all volumes (WARNING: deletes data)
docker-compose down -v
```

### Network Management
```bash
# List networks
docker network ls

# Inspect auth-network
docker network inspect auth-service_auth-network
```

## Production Deployment Tips

1. **Change Default Passwords**: Update RabbitMQ credentials in `.env`
2. **Use Environment-Specific Configs**: Set `SPRING_PROFILES_ACTIVE=prod`
3. **Enable SSL**: Configure SSL certificates for production
4. **Monitor Resources**: Use `docker stats` to monitor resource usage
5. **Set up Logging**: Configure centralized logging
6. **Regular Backups**: Backup RabbitMQ data regularly

## Next Steps

- Test integration with other services (user-service, gateway-service)
- Configure OAuth2/Keycloak settings for your environment
- Set up monitoring and alerting
- Review security configurations

## Support

For issues or questions, check:
- Service logs: `docker-compose logs auth-service`
- RabbitMQ Management UI: http://localhost:15672
- Application configuration: `src/main/resources/application.yml`

