#!/bin/bash
set -e

# QAVPN Hardened Relay Deployment Script
# Automates the deployment of a secure QAVPN relay node

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_NAME="qavpn-relay-hardened"
IMAGE_NAME="qavpn-relay:latest"
DEFAULT_PORT=9051

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose v2 is not available. Please install Docker Compose v2."
        exit 1
    fi
    
    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Test network connectivity
test_connectivity() {
    log_info "Testing connectivity to bootstrap nodes..."
    
    local bootstrap_nodes=("bootstrap1.qavpn.net" "bootstrap2.qavpn.net" "bootstrap3.qavpn.net")
    local connected=false
    
    for node in "${bootstrap_nodes[@]}"; do
        if timeout 5 nc -z "$node" 9051 2>/dev/null; then
            log_success "Connected to $node"
            connected=true
            break
        else
            log_warning "Cannot reach $node"
        fi
    done
    
    if [ "$connected" = false ]; then
        log_error "Cannot connect to any bootstrap nodes. Check your internet connection."
        log_info "The relay will still start but may have connectivity issues."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check port availability
check_port() {
    local port=${1:-$DEFAULT_PORT}
    
    log_info "Checking if port $port is available..."
    
    if netstat -ln 2>/dev/null | grep -q ":$port "; then
        log_error "Port $port is already in use"
        log_info "Please stop the service using port $port or choose a different port"
        exit 1
    fi
    
    log_success "Port $port is available"
}

# Build the Docker image
build_image() {
    log_info "Building QAVPN relay Docker image..."
    
    if docker build -t "$IMAGE_NAME" .; then
        log_success "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

# Deploy using Docker Compose
deploy_compose() {
    log_info "Deploying QAVPN relay using Docker Compose..."
    
    # Stop existing container if running
    if docker compose ps | grep -q "$CONTAINER_NAME"; then
        log_info "Stopping existing container..."
        docker compose down
    fi
    
    # Start the service
    if docker compose up --build -d; then
        log_success "QAVPN relay deployed successfully"
        
        # Wait a moment for container to start
        sleep 3
        
        # Check container status
        if docker compose ps | grep -q "Up"; then
            log_success "Container is running"
            
            # Show container info
            echo
            log_info "Container Information:"
            docker compose ps
            
            echo
            log_info "To view logs: docker compose logs -f qavpn-relay"
            log_info "To stop: docker compose down"
            log_info "To restart: docker compose restart"
            
        else
            log_error "Container failed to start properly"
            log_info "Check logs with: docker compose logs qavpn-relay"
            exit 1
        fi
    else
        log_error "Failed to deploy QAVPN relay"
        exit 1
    fi
}

# Deploy using plain Docker
deploy_docker() {
    local port=${1:-$DEFAULT_PORT}
    
    log_info "Deploying QAVPN relay using Docker..."
    
    # Stop existing container if running
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        log_info "Stopping existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
    
    # Run the container
    if docker run -d \
        --name "$CONTAINER_NAME" \
        --user 65532:65532 \
        --security-opt no-new-privileges:true \
        --cap-drop ALL \
        --memory 512m \
        --cpus 1.0 \
        --restart unless-stopped \
        -p "$port:$port/tcp" \
        -p "$port:$port/udp" \
        -e QAVPN_RELAY_PORT="$port" \
        -e QAVPN_VERBOSE=true \
        "$IMAGE_NAME"; then
        
        log_success "QAVPN relay deployed successfully"
        
        # Wait a moment for container to start
        sleep 3
        
        # Check container status
        if docker ps | grep -q "$CONTAINER_NAME"; then
            log_success "Container is running"
            
            # Show container info
            echo
            log_info "Container Information:"
            docker ps | grep "$CONTAINER_NAME"
            
            echo
            log_info "To view logs: docker logs -f $CONTAINER_NAME"
            log_info "To stop: docker stop $CONTAINER_NAME"
            log_info "To restart: docker restart $CONTAINER_NAME"
            
        else
            log_error "Container failed to start properly"
            log_info "Check logs with: docker logs $CONTAINER_NAME"
            exit 1
        fi
    else
        log_error "Failed to deploy QAVPN relay"
        exit 1
    fi
}

# Show status
show_status() {
    log_info "QAVPN Relay Status"
    echo "=================="
    
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        if docker compose ps 2>/dev/null | grep -q "qavpn-relay"; then
            echo "Docker Compose Status:"
            docker compose ps
            echo
            echo "Recent Logs:"
            docker compose logs --tail 10 qavpn-relay
        fi
    fi
    
    if docker ps | grep -q "$CONTAINER_NAME"; then
        echo "Docker Container Status:"
        docker ps | grep "$CONTAINER_NAME"
        echo
        echo "Recent Logs:"
        docker logs --tail 10 "$CONTAINER_NAME"
    fi
    
    if ! docker ps | grep -q "$CONTAINER_NAME" && ! docker compose ps 2>/dev/null | grep -q "qavpn-relay"; then
        log_warning "No QAVPN relay containers are currently running"
    fi
}

# Show help
show_help() {
    echo "QAVPN Hardened Relay Deployment Script"
    echo "======================================"
    echo
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo
    echo "Commands:"
    echo "  deploy-compose    Deploy using Docker Compose (recommended)"
    echo "  deploy-docker     Deploy using plain Docker"
    echo "  build            Build Docker image only"
    echo "  status           Show deployment status"
    echo "  stop             Stop running containers"
    echo "  logs             Show container logs"
    echo "  help             Show this help message"
    echo
    echo "Options:"
    echo "  -p, --port PORT  Specify relay port (default: 9051)"
    echo "  -v, --verbose    Enable verbose output"
    echo
    echo "Examples:"
    echo "  $0 deploy-compose"
    echo "  $0 deploy-docker -p 9052"
    echo "  $0 status"
    echo "  $0 logs"
}

# Stop containers
stop_containers() {
    log_info "Stopping QAVPN relay containers..."
    
    # Stop Docker Compose
    if docker compose ps 2>/dev/null | grep -q "qavpn-relay"; then
        docker compose down
        log_success "Docker Compose containers stopped"
    fi
    
    # Stop plain Docker container
    if docker ps | grep -q "$CONTAINER_NAME"; then
        docker stop "$CONTAINER_NAME"
        log_success "Docker container stopped"
    fi
    
    if ! docker ps | grep -q "$CONTAINER_NAME" && ! docker compose ps 2>/dev/null | grep -q "qavpn-relay"; then
        log_success "All QAVPN relay containers stopped"
    fi
}

# Show logs
show_logs() {
    if docker compose ps 2>/dev/null | grep -q "qavpn-relay"; then
        log_info "Showing Docker Compose logs..."
        docker compose logs -f qavpn-relay
    elif docker ps | grep -q "$CONTAINER_NAME"; then
        log_info "Showing Docker container logs..."
        docker logs -f "$CONTAINER_NAME"
    else
        log_error "No running QAVPN relay containers found"
        exit 1
    fi
}

# Main script logic
main() {
    local command=""
    local port=$DEFAULT_PORT
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            deploy-compose|deploy-docker|build|status|stop|logs|help)
                command="$1"
                shift
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Default command
    if [ -z "$command" ]; then
        command="deploy-compose"
    fi
    
    # Enable verbose mode
    if [ "$verbose" = true ]; then
        set -x
    fi
    
    # Execute command
    case $command in
        deploy-compose)
            check_prerequisites
            test_connectivity
            check_port "$port"
            deploy_compose
            ;;
        deploy-docker)
            check_prerequisites
            test_connectivity
            check_port "$port"
            build_image
            deploy_docker "$port"
            ;;
        build)
            check_prerequisites
            build_image
            ;;
        status)
            show_status
            ;;
        stop)
            stop_containers
            ;;
        logs)
            show_logs
            ;;
        help)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
