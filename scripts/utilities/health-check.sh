#!/bin/bash
# SOC Lab Health Check Script
# Comprehensive health monitoring for all lab components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CHECK_MODE="full"
OUTPUT_FORMAT="console"
LOG_FILE="/tmp/soc_lab_health_check.log"
REPORT_FILE=""
WAIT_TIMEOUT=30
VERBOSE=false

# Health check results
HEALTH_SCORE=0
TOTAL_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Usage function
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -m <mode>          Check mode: full, quick, aws, docker, network"
    echo "  -f <format>        Output format: console, json, html"
    echo "  -r <report_file>   Generate report file"
    echo "  -t <timeout>       Timeout for network checks (default: 30s)"
    echo "  -v, --verbose      Verbose output"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Check Modes:"
    echo "  full      - Complete health check (default)"
    echo "  quick     - Basic connectivity and service checks"
    echo "  aws       - AWS infrastructure checks only"
    echo "  docker    - Docker services checks only"
    echo "  network   - Network connectivity checks only"
    echo ""
    echo "Examples:"
    echo "  $0                    # Full health check"
    echo "  $0 -m quick -v       # Quick check with verbose output"
    echo "  $0 -m aws -f json    # AWS checks in JSON format"
    echo "  $0 -r health_report.html -f html  # Generate HTML report"
    exit 1
}

# Logging function
log() {
    local message="$1"
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $message" | tee -a "$LOG_FILE"
    if [ "$VERBOSE" = true ]; then
        echo "$message" >> "$LOG_FILE"
    fi
}

log_success() {
    local message="$1"
    echo -e "${GREEN}[PASS]${NC} $message" | tee -a "$LOG_FILE"
    ((HEALTH_SCORE++))
}

log_warning() {
    local message="$1"
    echo -e "${YELLOW}[WARN]${NC} $message" | tee -a "$LOG_FILE"
    ((WARNING_CHECKS++))
}

log_error() {
    local message="$1"
    echo -e "${RED}[FAIL]${NC} $message" | tee -a "$LOG_FILE"
    ((FAILED_CHECKS++))
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            CHECK_MODE="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -r|--report)
            REPORT_FILE="$2"
            shift 2
            ;;
        -t|--timeout)
            WAIT_TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate parameters
case $CHECK_MODE in
    full|quick|aws|docker|network) ;;
    *) echo "Invalid check mode: $CHECK_MODE"; usage ;;
esac

case $OUTPUT_FORMAT in
    console|json|html) ;;
    *) echo "Invalid output format: $OUTPUT_FORMAT"; usage ;;
esac

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local required_tools=("curl" "ping" "nc")
    
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            [ "$VERBOSE" = true ] && log_success "$tool is available"
        else
            log_error "Required tool missing: $tool"
            return 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

# AWS Infrastructure health checks
check_aws_infrastructure() {
    log "Checking AWS infrastructure..."
    ((TOTAL_CHECKS++))
    
    # Check if we're in terraform directory context
    if [ ! -f "terraform/terraform.tfstate" ]; then
        log_error "No Terraform state found - AWS resources may not be deployed"
        return 1
    fi
    
    cd terraform
    
    # Check terraform status
    if terraform show &> /dev/null; then
        log_success "Terraform state is valid"
        ((TOTAL_CHECKS++))
    else
        log_error "Terraform state is corrupted or invalid"
        cd ..
        return 1
    fi
    
    # Get resource IPs
    local wazuh_ip
    local jump_ip
    local kali_ip
    
    wazuh_ip=$(terraform output -raw wazuh_server_public_ip 2>/dev/null || echo "")
    jump_ip=$(terraform output -raw jump_box_public_ip 2>/dev/null || echo "")
    kali_ip=$(terraform output -raw kali_attacker_public_ip 2>/dev/null || echo "")
    
    # Check instance connectivity
    if [ -n "$wazuh_ip" ]; then
        ((TOTAL_CHECKS++))
        if ping -c 1 -W 3 "$wazuh_ip" &> /dev/null; then
            log_success "Wazuh server ($wazuh_ip) is reachable"
        else
            log_error "Wazuh server ($wazuh_ip) is not reachable"
        fi
    fi
    
    if [ -n "$jump_ip" ]; then
        ((TOTAL_CHECKS++))
        if ping -c 1 -W 3 "$jump_ip" &> /dev/null; then
            log_success "Jump box ($jump_ip) is reachable"
        else
            log_error "Jump box ($jump_ip) is not reachable"
        fi
    fi
    
    if [ -n "$kali_ip" ] && [ "$kali_ip" != "null" ]; then
        ((TOTAL_CHECKS++))
        if ping -c 1 -W 3 "$kali_ip" &> /dev/null; then
            log_success "Kali box ($kali_ip) is reachable"
        else
            log_error "Kali box ($kali_ip) is not reachable"
        fi
    fi
    
    cd ..
    log_success "AWS infrastructure checks completed"
}

# Docker services health checks
check_docker_services() {
    log "Checking Docker services..."
    
    if [ ! -d "docker" ]; then
        log_warning "Docker directory not found - skipping Docker checks"
        return 0
    fi
    
    cd docker
    
    # Check if docker-compose file exists
    ((TOTAL_CHECKS++))
    if [ -f "docker-compose.yml" ]; then
        log_success "Docker Compose configuration found"
    else
        log_error "Docker Compose configuration not found"
        cd ..
        return 1
    fi
    
    # Check if Docker is running
    ((TOTAL_CHECKS++))
    if docker info &> /dev/null; then
        log_success "Docker daemon is running"
    else
        log_error "Docker daemon is not running"
        cd ..
        return 1
    fi
    
    # Check Docker Compose services
    if docker-compose ps &> /dev/null; then
        local services
        services=$(docker-compose ps --services 2>/dev/null || echo "")
        
        if [ -n "$services" ]; then
            while IFS= read -r service; do
                ((TOTAL_CHECKS++))
                local status
                status=$(docker-compose ps "$service" | grep "$service" | awk '{print $4}' || echo "unknown")
                
                if [[ "$status" == "Up" ]]; then
                    log_success "Docker service '$service' is running"
                else
                    log_error "Docker service '$service' is not running (status: $status)"
                fi
            done <<< "$services"
        else
            log_warning "No Docker services found"
        fi
    else
        log_warning "Docker Compose not initialized or no services running"
    fi
    
    cd ..
    log_success "Docker services checks completed"
}

# Network connectivity checks
check_network_connectivity() {
    log "Checking network connectivity..."
    
    # Basic internet connectivity
    ((TOTAL_CHECKS++))
    if ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
        log_success "Internet connectivity available"
    else
        log_error "No internet connectivity"
    fi
    
    # DNS resolution
    ((TOTAL_CHECKS++))
    if nslookup google.com &> /dev/null; then
        log_success "DNS resolution working"
    else
        log_error "DNS resolution failed"
    fi
    
    # Check Wazuh services if available
    if [ -f "terraform/terraform.tfstate" ]; then
        cd terraform
        local wazuh_ip
        wazuh_ip=$(terraform output -raw wazuh_server_public_ip 2>/dev/null || echo "")
        
        if [ -n "$wazuh_ip" ]; then
            # Check Wazuh Dashboard (HTTPS)
            ((TOTAL_CHECKS++))
            if nc -z -w"$WAIT_TIMEOUT" "$wazuh_ip" 443 &> /dev/null; then
                log_success "Wazuh Dashboard port (443) is accessible"
            else
                log_error "Wazuh Dashboard port (443) is not accessible"
            fi
            
            # Check Wazuh API
            ((TOTAL_CHECKS++))
            if nc -z -w"$WAIT_TIMEOUT" "$wazuh_ip" 55000 &> /dev/null; then
                log_success "Wazuh API port (55000) is accessible"
            else
                log_error "Wazuh API port (55000) is not accessible"
            fi
            
            # Check actual Wazuh Dashboard response
            ((TOTAL_CHECKS++))
            if curl -k -s --connect-timeout "$WAIT_TIMEOUT" "https://$wazuh_ip:443" | grep -i "wazuh" &> /dev/null; then
                log_success "Wazuh Dashboard is responding correctly"
            else
                log_warning "Wazuh Dashboard is not responding or not ready"
            fi
        fi
        
        cd ..
    fi
    
    log_success "Network connectivity checks completed"
}

# Application-specific health checks
check_application_health() {
    log "Checking application health..."
    
    # Check if we can get terraform outputs
    if [ -f "terraform/terraform.tfstate" ]; then
        cd terraform
        
        # Check Wazuh agent connections
        local wazuh_ip
        wazuh_ip=$(terraform output -raw wazuh_server_public_ip 2>/dev/null || echo "")
        
        if [ -n "$wazuh_ip" ]; then
            ((TOTAL_CHECKS++))
            # Try to check agent status via API (simplified check)
            if curl -k -s --connect-timeout 10 "https://$wazuh_ip:55000" &> /dev/null; then
                log_success "Wazuh Manager API is accessible"
            else
                log_warning "Wazuh Manager API is not accessible - may still be starting"
            fi
        fi
        
        cd ..
    fi
    
    # Check vulnerable applications if deployed
    log "Checking for vulnerable applications..."
    
    # This would typically check internal network endpoints
    # For now, we'll just verify the configuration exists
    ((TOTAL_CHECKS++))
    if [ -f "docker/vulnerable-apps/docker-compose.yml" ]; then
        log_success "Vulnerable applications configuration found"
    else
        log_warning "Vulnerable applications configuration not found"
    fi
    
    log_success "Application health checks completed"
}

# Security checks
check_security_status() {
    log "Checking security configuration..."
    
    # Check for default credentials in configs
    ((TOTAL_CHECKS++))
    if grep -r "password123\|admin123\|default" terraform/ docker/ 2>/dev/null | grep -v "example" | grep -v "#" &> /dev/null; then
        log_warning "Potential default credentials found in configuration files"
    else
        log_success "No obvious default credentials found"
    fi
    
    # Check if sensitive files have proper permissions
    ((TOTAL_CHECKS++))
    local sensitive_files=("terraform/terraform.tfvars" "docker/.env")
    local perm_issues=false
    
    for file in "${sensitive_files[@]}"; do
        if [ -f "$file" ]; then
            local perms
            perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
            if [ "$perms" -gt 600 ]; then
                log_warning "File $file has overly permissive permissions ($perms)"
                perm_issues=true
            fi
        fi
    done
    
    if [ "$perm_issues" = false ]; then
        log_success "Sensitive files have appropriate permissions"
    fi
    
    # Check for exposed ports in security groups (simplified)
    ((TOTAL_CHECKS++))
    if [ -f "terraform/main.tf" ]; then
        if grep -q "0.0.0.0/0" terraform/*.tf; then
            log_warning "Found potential open security group rules (0.0.0.0/0)"
        else
            log_success "Security group rules appear to be restrictive"
        fi
    fi
    
    log_success "Security checks completed"
}

# Performance checks
check_performance() {
    log "Checking system performance..."
    
    # Check disk space
    ((TOTAL_CHECKS++))
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$disk_usage" -lt 80 ]; then
        log_success "Disk usage is acceptable ($disk_usage%)"
    elif [ "$disk_usage" -lt 90 ]; then
        log_warning "Disk usage is high ($disk_usage%)"
    else
        log_error "Disk usage is critically high ($disk_usage%)"
    fi
    
    # Check memory usage
    ((TOTAL_CHECKS++))
    if command -v free &> /dev/null; then
        local mem_usage
        mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
        
        if [ "$mem_usage" -lt 80 ]; then
            log_success "Memory usage is acceptable ($mem_usage%)"
        elif [ "$mem_usage" -lt 90 ]; then
            log_warning "Memory usage is high ($mem_usage%)"
        else
            log_error "Memory usage is critically high ($mem_usage%)"
        fi
    else
        log_warning "Cannot check memory usage - 'free' command not available"
    fi
    
    # Check load average
    ((TOTAL_CHECKS++))
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    if command -v nproc &> /dev/null; then
        local cpu_cores
        cpu_cores=$(nproc)
        local load_ratio
        load_ratio=$(echo "$load_avg / $cpu_cores" | bc -l 2>/dev/null || echo "0")
        
        if (( $(echo "$load_ratio < 0.7" | bc -l) )); then
            log_success "System load is acceptable ($load_avg)"
        elif (( $(echo "$load_ratio < 1.0" | bc -l) )); then
            log_warning "System load is high ($load_avg)"
        else
            log_error "System load is critically high ($load_avg)"
        fi
    else
        log_warning "Cannot assess load ratio - 'nproc' command not available"
    fi
    
    log_success "Performance checks completed"
}

# Generate health report
generate_report() {
    local overall_health
    local health_percentage
    
    if [ "$TOTAL_CHECKS" -gt 0 ]; then
        health_percentage=$(( (HEALTH_SCORE * 100) / TOTAL_CHECKS ))
    else
        health_percentage=0
    fi
    
    if [ "$health_percentage" -ge 90 ]; then
        overall_health="EXCELLENT"
    elif [ "$health_percentage" -ge 75 ]; then
        overall_health="GOOD"
    elif [ "$health_percentage" -ge 50 ]; then
        overall_health="FAIR"
    else
        overall_health="POOR"
    fi
    
    case $OUTPUT_FORMAT in
        json)
            generate_json_report "$overall_health" "$health_percentage"
            ;;
        html)
            generate_html_report "$overall_health" "$health_percentage"
            ;;
        *)
            generate_console_report "$overall_health" "$health_percentage"
            ;;
    esac
}

# Generate console report
generate_console_report() {
    local overall_health="$1"
    local health_percentage="$2"
    
    echo ""
    echo "SOC Lab Health Check Report"
    echo "==========================="
    echo "Date: $(date)"
    echo "Mode: $CHECK_MODE"
    echo ""
    echo "Overall Health: $overall_health ($health_percentage%)"
    echo ""
    echo "Summary:"
    echo "--------"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $HEALTH_SCORE"
    echo "Warnings: $WARNING_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo ""
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo "⚠️  Action Required: $FAILED_CHECKS critical issues found"
    elif [ "$WARNING_CHECKS" -gt 0 ]; then
        echo "⚡ Minor Issues: $WARNING_CHECKS warnings found"
    else
        echo "✅ All systems operational"
    fi
    
    echo ""
    echo "Recommendations:"
    echo "----------------"
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo "1. Review failed checks in the log above"
        echo "2. Ensure all AWS resources are properly deployed"
        echo "3. Check network connectivity and firewall rules"
        echo "4. Verify Docker services are running"
    elif [ "$WARNING_CHECKS" -gt 0 ]; then
        echo "1. Review warnings and consider addressing them"
        echo "2. Monitor system performance regularly"
        echo "3. Update any default credentials if found"
    else
        echo "1. System is healthy - continue regular monitoring"
        echo "2. Consider setting up automated health checks"
        echo "3. Review logs periodically for any issues"
    fi
    
    echo ""
    echo "Next Health Check: $(date -d '+1 hour' 2>/dev/null || date)"
}

# Generate JSON report
generate_json_report() {
    local overall_health="$1"
    local health_percentage="$2"
    local output_file="${REPORT_FILE:-health_report.json}"
    
    cat > "$output_file" << EOF
{
  "soc_lab_health_report": {
    "timestamp": "$(date -Iseconds)",
    "check_mode": "$CHECK_MODE",
    "overall_health": "$overall_health",
    "health_percentage": $health_percentage,
    "summary": {
      "total_checks": $TOTAL_CHECKS,
      "passed": $HEALTH_SCORE,
      "warnings": $WARNING_CHECKS,
      "failed": $FAILED_CHECKS
    },
    "status": {
      "critical_issues": $FAILED_CHECKS,
      "warnings": $WARNING_CHECKS,
      "operational": $(($TOTAL_CHECKS - $FAILED_CHECKS - $WARNING_CHECKS))
    },
    "recommendations": [
EOF
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        cat >> "$output_file" << EOF
      "Review failed checks and ensure all AWS resources are deployed",
      "Check network connectivity and firewall rules",
      "Verify Docker services are running properly"
EOF
    elif [ "$WARNING_CHECKS" -gt 0 ]; then
        cat >> "$output_file" << EOF
      "Review warnings and consider addressing them",
      "Monitor system performance regularly",
      "Update any default credentials if found"
EOF
    else
        cat >> "$output_file" << EOF
      "System is healthy - continue regular monitoring",
      "Consider setting up automated health checks",
      "Review logs periodically for any issues"
EOF
    fi
    
    cat >> "$output_file" << EOF
    ],
    "log_file": "$LOG_FILE"
  }
}
EOF
    
    echo "JSON report generated: $output_file"
}

# Generate HTML report
generate_html_report() {
    local overall_health="$1"
    local health_percentage="$2"
    local output_file="${REPORT_FILE:-health_report.html}"
    
    local health_color
    case $overall_health in
        EXCELLENT) health_color="#28a745" ;;
        GOOD) health_color="#6f42c1" ;;
        FAIR) health_color="#ffc107" ;;
        POOR) health_color="#dc3545" ;;
        *) health_color="#6c757d" ;;
    esac
    
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Lab Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .health-score { font-size: 3em; font-weight: bold; color: $health_color; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .status-card { padding: 20px; border-radius: 6px; text-align: center; }
        .passed { background: #d4edda; color: #155724; }
        .warnings { background: #fff3cd; color: #856404; }
        .failed { background: #f8d7da; color: #721c24; }
        .recommendations { background: #e2e3e5; padding: 20px; border-radius: 6px; margin-top: 20px; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
        ul { text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SOC Lab Health Report</h1>
            <div class="health-score">$health_percentage%</div>
            <div style="font-size: 1.2em; color: $health_color; margin: 10px 0;">$overall_health</div>
            <div class="timestamp">Generated: $(date)</div>
        </div>
        
        <div class="status-grid">
            <div class="status-card passed">
                <h3>$HEALTH_SCORE</h3>
                <p>Checks Passed</p>
            </div>
            <div class="status-card warnings">
                <h3>$WARNING_CHECKS</h3>
                <p>Warnings</p>
            </div>
            <div class="status-card failed">
                <h3>$FAILED_CHECKS</h3>
                <p>Failed Checks</p>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
EOF
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        cat >> "$output_file" << EOF
                <li>Review failed checks and ensure all AWS resources are properly deployed</li>
                <li>Check network connectivity and firewall rules</li>
                <li>Verify Docker services are running correctly</li>
EOF
    elif [ "$WARNING_CHECKS" -gt 0 ]; then
        cat >> "$output_file" << EOF
                <li>Review warnings and consider addressing them</li>
                <li>Monitor system performance regularly</li>
                <li>Update any default credentials if found</li>
EOF
    else
        cat >> "$output_file" << EOF
                <li>System is healthy - continue regular monitoring</li>
                <li>Consider setting up automated health checks</li>
                <li>Review logs periodically for any issues</li>
EOF
    fi
    
    cat >> "$output_file" << EOF
            </ul>
        </div>
        
        <div style="margin-top: 30px; text-align: center; color: #6c757d; font-size: 0.9em;">
            <p>Check Mode: $CHECK_MODE | Log File: $LOG_FILE</p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo "HTML report generated: $output_file"
}

# Main execution
main() {
    echo ""
    echo "SOC Lab Health Check"
    echo "===================="
    echo "Mode: $CHECK_MODE"
    echo "Format: $OUTPUT_FORMAT"
    [ "$VERBOSE" = true ] && echo "Verbose: enabled"
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    # Execute checks based on mode
    case $CHECK_MODE in
        full)
            check_aws_infrastructure
            check_docker_services
            check_network_connectivity
            check_application_health
            check_security_status
            check_performance
            ;;
        quick)
            check_aws_infrastructure
            check_network_connectivity
            ;;
        aws)
            check_aws_infrastructure
            ;;
        docker)
            check_docker_services
            ;;
        network)
            check_network_connectivity
            ;;
    esac
    
    # Generate report
    generate_report
    
    # Exit with appropriate code
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        exit 1
    elif [ "$WARNING_CHECKS" -gt 0 ]; then
        exit 2
    else
        exit 0
    fi
}

# Run main function
main "$@"