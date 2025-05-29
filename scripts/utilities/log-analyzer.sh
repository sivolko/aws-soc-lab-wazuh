#!/bin/bash
# SOC Lab Log Analyzer
# Analyze logs from various sources in the SOC Lab

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
LOG_SOURCE="all"
TIME_RANGE="1h"
OUTPUT_DIR="/tmp/log_analysis"
ANALYSIS_TYPE="security"
VERBOSE=false
REPORT_FORMAT="text"
THREAT_HUNTING_MODE=false

# Usage function
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -s <source>        Log source: all, wazuh, system, web, auth, docker"
    echo "  -t <time_range>    Time range: 1h, 6h, 24h, 7d (default: 1h)"
    echo "  -a <analysis>      Analysis type: security, performance, errors, all"
    echo "  -o <output_dir>    Output directory (default: /tmp/log_analysis)"
    echo "  -f <format>        Report format: text, json, csv"
    echo "  -H, --hunt         Enable threat hunting mode"
    echo "  -v, --verbose      Verbose output"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Log Sources:"
    echo "  all      - Analyze all available log sources"
    echo "  wazuh    - Wazuh alerts and manager logs"
    echo "  system   - System logs (syslog, auth.log)"
    echo "  web      - Web server access and error logs"
    echo "  auth     - Authentication logs"
    echo "  docker   - Docker container logs"
    echo ""
    echo "Analysis Types:"
    echo "  security      - Focus on security events and threats"
    echo "  performance   - System and application performance"
    echo "  errors        - Error messages and failures"
    echo "  all           - Comprehensive analysis"
    echo ""
    echo "Examples:"
    echo "  $0 -s wazuh -t 6h -a security"
    echo "  $0 -s all -t 24h -H -f json"
    echo "  $0 -s auth -t 1h -v"
    exit 1
}

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
    [ "$VERBOSE" = true ] && echo "$1" >> "$OUTPUT_DIR/analyzer.log"
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

log_info() {
    echo -e "${PURPLE}[INFO]${NC} $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--source)
            LOG_SOURCE="$2"
            shift 2
            ;;
        -t|--time)
            TIME_RANGE="$2"
            shift 2
            ;;
        -a|--analysis)
            ANALYSIS_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--format)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        -H|--hunt)
            THREAT_HUNTING_MODE=true
            shift
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

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Convert time range to minutes for processing
convert_time_range() {
    case $TIME_RANGE in
        1h) echo 60 ;;
        6h) echo 360 ;;
        24h) echo 1440 ;;
        7d) echo 10080 ;;
        *) echo 60 ;; # default to 1 hour
    esac
}

# Get timestamp for filtering
get_start_time() {
    local minutes
    minutes=$(convert_time_range)
    date -d "$minutes minutes ago" '+%Y-%m-%d %H:%M:%S'
}

# Analyze Wazuh logs
analyze_wazuh_logs() {
    log "Analyzing Wazuh logs..."
    
    local wazuh_results="$OUTPUT_DIR/wazuh_analysis.txt"
    local start_time
    start_time=$(get_start_time)
    
    echo "Wazuh Log Analysis - $(date)" > "$wazuh_results"
    echo "Time Range: $TIME_RANGE (from $start_time)" >> "$wazuh_results"
    echo "========================================" >> "$wazuh_results"
    echo "" >> "$wazuh_results"
    
    # Check if we can access Wazuh logs via Docker
    if [ -d "docker" ] && [ -f "docker/docker-compose.yml" ]; then
        cd docker
        
        # Get Wazuh alerts
        if docker-compose ps wazuh-manager | grep -q "Up"; then
            log "Extracting Wazuh alerts..."
            
            # Get recent alerts
            echo "Recent Wazuh Alerts:" >> "$wazuh_results"
            echo "--------------------" >> "$wazuh_results"
            
            # Extract alerts from container
            docker-compose exec -T wazuh-manager find /var/ossec/logs/alerts -name "alerts.json" -newer /tmp/start_time 2>/dev/null | head -100 >> "$wazuh_results" || {
                echo "Could not access Wazuh alerts directly" >> "$wazuh_results"
            }
            
            echo "" >> "$wazuh_results"
            
            # Get agent status
            echo "Wazuh Agent Status:" >> "$wazuh_results"
            echo "-------------------" >> "$wazuh_results"
            docker-compose exec -T wazuh-manager /var/ossec/bin/agent_control -lc 2>/dev/null >> "$wazuh_results" || {
                echo "Could not retrieve agent status" >> "$wazuh_results"
            }
            
            echo "" >> "$wazuh_results"
            
            # Get manager status
            echo "Wazuh Manager Status:" >> "$wazuh_results"
            echo "--------------------" >> "$wazuh_results"
            docker-compose exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null >> "$wazuh_results" || {
                echo "Could not retrieve manager status" >> "$wazuh_results"
            }
        else
            echo "Wazuh Manager container is not running" >> "$wazuh_results"
        fi
        
        cd ..
    else
        echo "Docker configuration not found - checking local Wazuh installation" >> "$wazuh_results"
        
        # Check for local Wazuh installation
        if [ -d "/var/ossec/logs" ]; then
            log "Found local Wazuh installation"
            
            # Analyze alerts
            if [ -f "/var/ossec/logs/alerts/alerts.json" ]; then
                echo "Recent Alerts from local installation:" >> "$wazuh_results"
                tail -100 /var/ossec/logs/alerts/alerts.json >> "$wazuh_results" 2>/dev/null || {
                    echo "Could not read local alerts" >> "$wazuh_results"
                }
            fi
        else
            echo "No Wazuh installation found" >> "$wazuh_results"
        fi
    fi
    
    # Analyze the results for security events
    if [ "$ANALYSIS_TYPE" = "security" ] || [ "$ANALYSIS_TYPE" = "all" ]; then
        echo "" >> "$wazuh_results"
        echo "Security Event Analysis:" >> "$wazuh_results"
        echo "------------------------" >> "$wazuh_results"
        
        # Count different types of alerts
        local alert_summary="$OUTPUT_DIR/wazuh_alert_summary.txt"
        
        echo "Alert Summary:" > "$alert_summary"
        echo "Total alerts analyzed: $(wc -l < "$wazuh_results" || echo 0)" >> "$alert_summary"
        
        # Look for specific attack patterns
        if grep -i "authentication\|login\|ssh\|brute" "$wazuh_results" &>/dev/null; then
            echo "Authentication events detected" >> "$alert_summary"
        fi
        
        if grep -i "injection\|sql\|xss\|command" "$wazuh_results" &>/dev/null; then
            echo "Injection attack indicators found" >> "$alert_summary"
        fi
        
        if grep -i "malware\|virus\|trojan" "$wazuh_results" &>/dev/null; then
            echo "Malware detection alerts found" >> "$alert_summary"
        fi
        
        cat "$alert_summary" >> "$wazuh_results"
    fi
    
    log_success "Wazuh log analysis completed: $wazuh_results"
}

# Analyze system logs
analyze_system_logs() {
    log "Analyzing system logs..."
    
    local system_results="$OUTPUT_DIR/system_analysis.txt"
    local start_time
    start_time=$(get_start_time)
    
    echo "System Log Analysis - $(date)" > "$system_results"
    echo "Time Range: $TIME_RANGE (from $start_time)" >> "$system_results"
    echo "====================================" >> "$system_results"
    echo "" >> "$system_results"
    
    # Analyze syslog
    if [ -f "/var/log/syslog" ]; then
        echo "Recent System Log Entries:" >> "$system_results"
        echo "--------------------------" >> "$system_results"
        
        # Get recent entries
        awk -v start_time="$start_time" '$0 >= start_time' /var/log/syslog | tail -50 >> "$system_results" 2>/dev/null || {
            tail -50 /var/log/syslog >> "$system_results" 2>/dev/null || echo "Could not read syslog" >> "$system_results"
        }
        
        echo "" >> "$system_results"
    fi
    
    # Analyze auth log
    if [ -f "/var/log/auth.log" ]; then
        echo "Authentication Log Analysis:" >> "$system_results"
        echo "---------------------------" >> "$system_results"
        
        # Recent auth events
        tail -50 /var/log/auth.log >> "$system_results" 2>/dev/null || {
            echo "Could not read auth.log" >> "$system_results"
        }
        
        echo "" >> "$system_results"
        
        # Failed login attempts
        echo "Failed Login Attempts:" >> "$system_results"
        echo "----------------------" >> "$system_results"
        grep -i "failed\|failure\|invalid" /var/log/auth.log | tail -20 >> "$system_results" 2>/dev/null || {
            echo "No failed login attempts found or could not read log" >> "$system_results"
        }
        
        echo "" >> "$system_results"
    fi
    
    # Analyze kernel messages
    if [ -f "/var/log/kern.log" ]; then
        echo "Kernel Log Analysis:" >> "$system_results"
        echo "-------------------" >> "$system_results"
        
        # Recent kernel messages
        tail -30 /var/log/kern.log >> "$system_results" 2>/dev/null || {
            echo "Could not read kern.log" >> "$system_results"
        }
        
        echo "" >> "$system_results"
    fi
    
    # System performance metrics
    if [ "$ANALYSIS_TYPE" = "performance" ] || [ "$ANALYSIS_TYPE" = "all" ]; then
        echo "System Performance Metrics:" >> "$system_results"
        echo "---------------------------" >> "$system_results"
        
        echo "Current System Load:" >> "$system_results"
        uptime >> "$system_results" 2>/dev/null
        
        echo "" >> "$system_results"
        echo "Memory Usage:" >> "$system_results"
        free -h >> "$system_results" 2>/dev/null
        
        echo "" >> "$system_results"
        echo "Disk Usage:" >> "$system_results"
        df -h >> "$system_results" 2>/dev/null
        
        echo "" >> "$system_results"
    fi
    
    log_success "System log analysis completed: $system_results"
}

# Analyze authentication logs
analyze_auth_logs() {
    log "Analyzing authentication logs..."
    
    local auth_results="$OUTPUT_DIR/auth_analysis.txt"
    
    echo "Authentication Log Analysis - $(date)" > "$auth_results"
    echo "Time Range: $TIME_RANGE" >> "$auth_results"
    echo "==================================" >> "$auth_results"
    echo "" >> "$auth_results"
    
    # SSH authentication analysis
    echo "SSH Authentication Events:" >> "$auth_results"
    echo "--------------------------" >> "$auth_results"
    
    if [ -f "/var/log/auth.log" ]; then
        # Successful SSH logins
        echo "Successful SSH Logins:" >> "$auth_results"
        grep -i "Accepted" /var/log/auth.log | tail -10 >> "$auth_results" 2>/dev/null || echo "No successful SSH logins" >> "$auth_results"
        
        echo "" >> "$auth_results"
        
        # Failed SSH attempts
        echo "Failed SSH Attempts:" >> "$auth_results"
        grep -i "Failed password\|authentication failure" /var/log/auth.log | tail -20 >> "$auth_results" 2>/dev/null || echo "No failed SSH attempts" >> "$auth_results"
        
        echo "" >> "$auth_results"
        
        # Brute force detection
        echo "Potential Brute Force Attacks:" >> "$auth_results"
        echo "------------------------------" >> "$auth_results"
        
        # Count failed attempts by IP
        grep -i "Failed password" /var/log/auth.log 2>/dev/null | 
        awk '{for(i=1;i<=NF;i++) if($i~/from/) print $(i+1)}' | 
        sort | uniq -c | sort -nr | head -10 >> "$auth_results" || echo "No brute force patterns detected" >> "$auth_results"
        
        echo "" >> "$auth_results"
    else
        echo "Auth log not accessible" >> "$auth_results"
    fi
    
    # Sudo usage analysis
    echo "Sudo Usage Analysis:" >> "$auth_results"
    echo "-------------------" >> "$auth_results"
    
    if [ -f "/var/log/auth.log" ]; then
        grep -i "sudo" /var/log/auth.log | tail -15 >> "$auth_results" 2>/dev/null || echo "No sudo usage recorded" >> "$auth_results"
    else
        echo "Cannot analyze sudo usage - auth log not accessible" >> "$auth_results"
    fi
    
    echo "" >> "$auth_results"
    
    log_success "Authentication log analysis completed: $auth_results"
}

# Analyze Docker logs
analyze_docker_logs() {
    log "Analyzing Docker logs..."
    
    local docker_results="$OUTPUT_DIR/docker_analysis.txt"
    
    echo "Docker Log Analysis - $(date)" > "$docker_results"
    echo "Time Range: $TIME_RANGE" >> "$docker_results"
    echo "============================" >> "$docker_results"
    echo "" >> "$docker_results"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo "Docker not available for analysis" >> "$docker_results"
        return
    fi
    
    # List running containers
    echo "Running Containers:" >> "$docker_results"
    echo "------------------" >> "$docker_results"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" >> "$docker_results" 2>/dev/null || {
        echo "Could not list Docker containers" >> "$docker_results"
    }
    
    echo "" >> "$docker_results"
    
    # Analyze logs from Wazuh containers if available
    if [ -d "docker" ] && [ -f "docker/docker-compose.yml" ]; then
        cd docker
        
        echo "Wazuh Container Logs:" >> "../docker_results"
        echo "--------------------" >> "../docker_results"
        
        # Get logs from each Wazuh component
        for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
            if docker-compose ps "$service" | grep -q "Up"; then
                echo "" >> "../docker_results"
                echo "=== $service logs ==" >> "../docker_results"
                docker-compose logs --tail=20 "$service" >> "../docker_results" 2>/dev/null || {
                    echo "Could not retrieve logs for $service" >> "../docker_results"
                }
            fi
        done
        
        cd ..
    fi
    
    # Analyze container resource usage
    echo "" >> "$docker_results"
    echo "Container Resource Usage:" >> "$docker_results"
    echo "------------------------" >> "$docker_results"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" >> "$docker_results" 2>/dev/null || {
        echo "Could not retrieve container stats" >> "$docker_results"
    }
    
    log_success "Docker log analysis completed: $docker_results"
}

# Threat hunting analysis
threat_hunting_analysis() {
    log "Performing threat hunting analysis..."
    
    local hunting_results="$OUTPUT_DIR/threat_hunting.txt"
    
    echo "Threat Hunting Analysis - $(date)" > "$hunting_results"
    echo "Time Range: $TIME_RANGE" >> "$hunting_results"
    echo "================================" >> "$hunting_results"
    echo "" >> "$hunting_results"
    
    # MITRE ATT&CK technique hunting
    echo "MITRE ATT&CK Technique Indicators:" >> "$hunting_results"
    echo "----------------------------------" >> "$hunting_results"
    
    # T1110 - Brute Force
    echo "T1110 - Brute Force Indicators:" >> "$hunting_results"
    if [ -f "/var/log/auth.log" ]; then
        local brute_force_count
        brute_force_count=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
        echo "Failed password attempts: $brute_force_count" >> "$hunting_results"
        
        if [ "$brute_force_count" -gt 10 ]; then
            echo "⚠️  HIGH: Potential brute force activity detected" >> "$hunting_results"
        fi
    fi
    
    echo "" >> "$hunting_results"
    
    # T1190 - Exploit Public-Facing Application
    echo "T1190 - Web Application Exploitation:" >> "$hunting_results"
    
    # Check for common web attack patterns in logs
    local web_attack_patterns=("union select" "' or 1=1" "<script" "../../../" "cmd.exe" "eval(" "system(")
    
    for pattern in "${web_attack_patterns[@]}"; do
        local count
        count=$(grep -ri "$pattern" /var/log/ 2>/dev/null | wc -l || echo 0)
        if [ "$count" -gt 0 ]; then
            echo "Pattern '$pattern' found $count times" >> "$hunting_results"
        fi
    done
    
    echo "" >> "$hunting_results"
    
    # T1059 - Command and Scripting Interpreter
    echo "T1059 - Command Execution Indicators:" >> "$hunting_results"
    
    # Look for suspicious command execution
    local suspicious_commands=("powershell" "cmd.exe" "bash -c" "sh -c" "python -c" "perl -e")
    
    for cmd in "${suspicious_commands[@]}"; do
        local count
        count=$(grep -ri "$cmd" /var/log/ 2>/dev/null | wc -l || echo 0)
        if [ "$count" -gt 0 ]; then
            echo "Suspicious command '$cmd' found $count times" >> "$hunting_results"
        fi
    done
    
    echo "" >> "$hunting_results"
    
    # Network-based indicators
    echo "Network-based Threat Indicators:" >> "$hunting_results"
    echo "--------------------------------" >> "$hunting_results"
    
    # Check for unusual network connections
    if command -v netstat &> /dev/null; then
        echo "Current Network Connections:" >> "$hunting_results"
        netstat -tulpn | grep LISTEN >> "$hunting_results" 2>/dev/null
    fi
    
    echo "" >> "$hunting_results"
    
    # Check for indicators of compromise
    echo "Indicators of Compromise (IoCs):" >> "$hunting_results"
    echo "--------------------------------" >> "$hunting_results"
    
    # File integrity indicators
    echo "File System Indicators:" >> "$hunting_results"
    
    # Check for recently modified system files
    find /etc /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null | head -10 >> "$hunting_results" || {
        echo "Could not check for recently modified system files" >> "$hunting_results"
    }
    
    echo "" >> "$hunting_results"
    
    # Process analysis
    echo "Process Analysis:" >> "$hunting_results"
    echo "----------------" >> "$hunting_results"
    
    # Look for suspicious processes
    ps aux | grep -E "(nc|netcat|nmap|sqlmap|nikto|hydra|john)" | grep -v grep >> "$hunting_results" || {
        echo "No obviously suspicious processes detected" >> "$hunting_results"
    }
    
    echo "" >> "$hunting_results"
    
    log_success "Threat hunting analysis completed: $hunting_results"
}

# Generate summary report
generate_summary_report() {
    local summary_file="$OUTPUT_DIR/analysis_summary.txt"
    
    log "Generating analysis summary..."
    
    echo "SOC Lab Log Analysis Summary" > "$summary_file"
    echo "============================" >> "$summary_file"
    echo "Analysis Date: $(date)" >> "$summary_file"
    echo "Time Range: $TIME_RANGE" >> "$summary_file"
    echo "Log Sources: $LOG_SOURCE" >> "$summary_file"
    echo "Analysis Type: $ANALYSIS_TYPE" >> "$summary_file"
    echo "Threat Hunting: $THREAT_HUNTING_MODE" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count total events analyzed
    local total_lines=0
    for file in "$OUTPUT_DIR"/*.txt; do
        if [ -f "$file" ] && [ "$file" != "$summary_file" ]; then
            local lines
            lines=$(wc -l < "$file" 2>/dev/null || echo 0)
            total_lines=$((total_lines + lines))
        fi
    done
    
    echo "Total log lines analyzed: $total_lines" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Key findings
    echo "Key Findings:" >> "$summary_file"
    echo "-------------" >> "$summary_file"
    
    # Security findings
    if [ -f "$OUTPUT_DIR/auth_analysis.txt" ]; then
        local failed_logins
        failed_logins=$(grep -c "Failed" "$OUTPUT_DIR/auth_analysis.txt" 2>/dev/null || echo 0)
        echo "Failed authentication attempts: $failed_logins" >> "$summary_file"
    fi
    
    # System health
    if [ -f "$OUTPUT_DIR/system_analysis.txt" ]; then
        echo "System logs analyzed successfully" >> "$summary_file"
    fi
    
    # Wazuh findings
    if [ -f "$OUTPUT_DIR/wazuh_analysis.txt" ]; then
        echo "Wazuh SIEM logs processed" >> "$summary_file"
    fi
    
    # Threat hunting results
    if [ "$THREAT_HUNTING_MODE" = true ] && [ -f "$OUTPUT_DIR/threat_hunting.txt" ]; then
        echo "Threat hunting analysis completed" >> "$summary_file"
        
        # Check for high-priority findings
        if grep -q "HIGH:" "$OUTPUT_DIR/threat_hunting.txt"; then
            echo "⚠️  HIGH PRIORITY threats detected - review threat hunting report" >> "$summary_file"
        fi
    fi
    
    echo "" >> "$summary_file"
    
    # Recommendations
    echo "Recommendations:" >> "$summary_file"
    echo "---------------" >> "$summary_file"
    echo "1. Review individual analysis files for detailed findings" >> "$summary_file"
    echo "2. Investigate any high-priority security events" >> "$summary_file"
    echo "3. Set up automated log monitoring for continuous analysis" >> "$summary_file"
    echo "4. Correlate findings with Wazuh SIEM alerts" >> "$summary_file"
    
    if [ "$THREAT_HUNTING_MODE" = true ]; then
        echo "5. Follow up on threat hunting indicators" >> "$summary_file"
        echo "6. Implement additional detection rules based on findings" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    
    # Files generated
    echo "Analysis Files Generated:" >> "$summary_file"
    echo "------------------------" >> "$summary_file"
    for file in "$OUTPUT_DIR"/*.txt; do
        if [ -f "$file" ]; then
            echo "$(basename "$file")" >> "$summary_file"
        fi
    done
    
    log_success "Summary report generated: $summary_file"
}

# Convert to JSON format
convert_to_json() {
    if [ "$REPORT_FORMAT" != "json" ]; then
        return
    fi
    
    log "Converting reports to JSON format..."
    
    local json_file="$OUTPUT_DIR/log_analysis.json"
    
    {
        echo "{"
        echo "  \"log_analysis_report\": {"
        echo "    \"timestamp\": \"$(date -Iseconds)\","
        echo "    \"time_range\": \"$TIME_RANGE\","
        echo "    \"log_source\": \"$LOG_SOURCE\","
        echo "    \"analysis_type\": \"$ANALYSIS_TYPE\","
        echo "    \"threat_hunting\": $THREAT_HUNTING_MODE,"
        echo "    \"files_analyzed\": ["
        
        local first=true
        for file in "$OUTPUT_DIR"/*.txt; do
            if [ -f "$file" ]; then
                [ "$first" = false ] && echo ","
                echo "      \"$(basename "$file")\""
                first=false
            fi
        done
        
        echo "    ],"
        echo "    \"output_directory\": \"$OUTPUT_DIR\""
        echo "  }"
        echo "}"
    } > "$json_file"
    
    log_success "JSON report generated: $json_file"
}

# Main execution
main() {
    echo ""
    echo "SOC Lab Log Analyzer"
    echo "===================="
    echo "Source: $LOG_SOURCE"
    echo "Time Range: $TIME_RANGE"
    echo "Analysis: $ANALYSIS_TYPE"
    echo "Output: $OUTPUT_DIR"
    [ "$THREAT_HUNTING_MODE" = true ] && echo "Threat Hunting: Enabled"
    echo ""
    
    # Execute analysis based on source
    case $LOG_SOURCE in
        all)
            analyze_wazuh_logs
            analyze_system_logs
            analyze_auth_logs
            analyze_docker_logs
            [ "$THREAT_HUNTING_MODE" = true ] && threat_hunting_analysis
            ;;
        wazuh)
            analyze_wazuh_logs
            ;;
        system)
            analyze_system_logs
            ;;
        auth)
            analyze_auth_logs
            ;;
        docker)
            analyze_docker_logs
            ;;
        web)
            log_warning "Web log analysis not yet implemented"
            ;;
        *)
            log_error "Invalid log source: $LOG_SOURCE"
            exit 1
            ;;
    esac
    
    # Threat hunting if requested
    if [ "$THREAT_HUNTING_MODE" = true ] && [ "$LOG_SOURCE" != "all" ]; then
        threat_hunting_analysis
    fi
    
    # Generate summary
    generate_summary_report
    
    # Convert to requested format
    convert_to_json
    
    echo ""
    log_success "Log analysis completed successfully"
    echo "📁 Results directory: $OUTPUT_DIR"
    echo "📋 Summary: $OUTPUT_DIR/analysis_summary.txt"
    [ "$THREAT_HUNTING_MODE" = true ] && echo "🔍 Threat hunting: $OUTPUT_DIR/threat_hunting.txt"
    echo ""
}

# Run main function
main "$@"