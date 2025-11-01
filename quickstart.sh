#!/bin/bash
set -e

echo "====================================="
echo "IAM Copilot - Quick Start Setup"
echo "====================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker compose &> /dev/null; then
    echo "Error: Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Copy .env.example to .env if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo ""
    echo "⚠️  IMPORTANT: Please edit .env file with your AWS credentials:"
    echo "   - AWS_ACCESS_KEY_ID"
    echo "   - AWS_SECRET_ACCESS_KEY"
    echo "   - AWS_REGION (default: us-east-1)"
    echo "   - DB_PASSWORD (set a secure password)"
    echo "   - SECRET_KEY (generate with: openssl rand -hex 32)"
    echo ""
    read -p "Press Enter after updating .env file..."
fi

# Build and start services
echo ""
echo "Building Docker images (this may take a few minutes)..."
docker compose build

echo ""
echo "Starting all services..."
docker compose up -d

echo ""
echo "Waiting for services to be ready..."
sleep 15

# Check if services are healthy
echo ""
echo "Checking service health..."

if curl -s http://localhost:8000/health > /dev/null; then
    echo "✓ API is healthy"
else
    echo "✗ API is not responding. Check logs with: docker compose logs api"
fi

if docker compose exec -T db pg_isready -U admin > /dev/null 2>&1; then
    echo "✓ Database is ready"
else
    echo "✗ Database is not ready. Check logs with: docker compose logs db"
fi

if docker compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo "✓ Redis is ready"
else
    echo "✗ Redis is not ready. Check logs with: docker compose logs redis"
fi

echo ""
echo "====================================="
echo "Setup Complete!"
echo "====================================="
echo ""
echo "Application is running at:"
echo "  Frontend:  http://localhost:3000"
echo "  API:       http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "Useful commands:"
echo "  View logs:        docker compose logs -f"
echo "  Stop services:    docker compose down"
echo "  Restart:          docker compose restart"
echo "  Run migrations:   docker compose exec api alembic upgrade head"
echo ""
echo "Or use the Makefile:"
echo "  make help         Show all available commands"
echo "  make logs         View logs"
echo "  make down         Stop services"
echo ""
