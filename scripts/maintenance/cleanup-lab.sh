#!/bin/bash
# SOC Lab Cleanup Script
# Safely destroys AWS resources and cleans up local files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CLEANUP_MODE="interactive"
BACKUP_BEFORE_DESTROY=true
CLEANUP_LOCAL_FILES=false
FORCE_DESTROY=false
LOG_FILE="/tmp/soc_lab_cleanup.log"

# Usage function
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -m <mode>          Cleanup mode: interactive, auto, backup-only"
    echo "  -f, --force        Force destroy without confirmation"
    echo "  -b, --no-backup    Skip backup before destruction"
    echo "  -l, --local        Also cleanup local files"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Cleanup Modes:"
    echo "  interactive        Ask for confirmation at each step (default)"
    echo "  auto              Automatic cleanup with minimal prompts"
    echo "  backup-only       Only create backup, don't destroy resources"
    echo ""
    echo "Examples:"
    echo "  $0                 # Interactive cleanup"
    echo "  $0 -m auto -f     # Automatic cleanup without confirmation"
    echo "  $0 -m backup-only # Create backup only"
    echo "  $0 -f -l          # Force destroy and cleanup local files"
    exit 1
}

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            CLEANUP_MODE="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_DESTROY=true
            shift
            ;;
        -b|--no-backup)
            BACKUP_BEFORE_DESTROY=false
            shift
            ;;
        -l|--local)
            CLEANUP_LOCAL_FILES=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate cleanup mode
case $CLEANUP_MODE in
    interactive|auto|backup-only) ;;
    *) log_error "Invalid cleanup mode: $CLEANUP_MODE"; usage ;;
esac

# Check if we're in the correct directory
check_environment() {
    log "Checking environment..."
    
    if [ ! -f "terraform/main.tf" ]; then
        log_error "Not in SOC Lab directory. Please run from the project root."
        exit 1
    fi
    
    if [ ! -f "terraform/terraform.tfstate" ]; then
        log_warning "No Terraform state file found. Resources may already be destroyed."
        return 1
    fi
    
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform not found. Please install Terraform."
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install AWS CLI."
        exit 1
    fi
    
    log_success "Environment check passed"
    return 0
}

# Display current resources
show_current_resources() {
    log "Retrieving current AWS resources..."
    
    cd terraform
    
    if terraform show &> /dev/null; then
        echo ""
        echo "Current AWS Resources:"
        echo "====================="
        
        # Get key outputs
        if terraform output &> /dev/null; then
            echo "Wazuh Server: $(terraform output -raw wazuh_server_public_ip 2>/dev/null || echo 'N/A')"
            echo "Jump Box: $(terraform output -raw jump_box_public_ip 2>/dev/null || echo 'N/A')"
            echo "Kali Box: $(terraform output -raw kali_attacker_public_ip 2>/dev/null || echo 'N/A')"
            echo "VPC ID: $(terraform output -raw vpc_id 2>/dev/null || echo 'N/A')"
        fi
        
        echo ""
        echo "Resource Summary:"
        terraform state list | grep -E "(aws_instance|aws_vpc|aws_s3_bucket)" | wc -l | xargs echo "Total resources:"
        
        echo ""
        echo "Estimated Monthly Cost: ~$99 USD"
    else
        log_warning "Unable to retrieve resource information"
    fi
    
    cd ..
}

# Create backup before destruction
create_backup() {
    if [ "$BACKUP_BEFORE_DESTROY" = false ]; then
        log "Skipping backup as requested"
        return 0
    fi
    
    log "Creating backup before cleanup..."
    
    local backup_dir="soc-lab-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup Terraform state and configuration
    log "Backing up Terraform configuration..."
    cp -r terraform/ "$backup_dir/"
    
    # Backup Docker configuration
    if [ -d "docker" ]; then
        log "Backing up Docker configuration..."
        cp -r docker/ "$backup_dir/"
    fi
    
    # Backup scripts and documentation
    log "Backing up scripts and documentation..."
    cp -r scripts/ "$backup_dir/" 2>/dev/null || log_warning "No scripts directory found"
    cp -r docs/ "$backup_dir/" 2>/dev/null || log_warning "No docs directory found"
    
    # Backup deployment summary
    [ -f "deployment-summary.txt" ] && cp deployment-summary.txt "$backup_dir/"
    [ -f "deployment-outputs.txt" ] && cp deployment-outputs.txt "$backup_dir/"
    
    # Create backup metadata
    cat > "$backup_dir/backup-info.txt" << EOF
SOC Lab Backup Information
=========================
Backup Date: $(date)
Backup Directory: $backup_dir
Original Location: $(pwd)
Terraform Version: $(terraform version 2>/dev/null | head -1 || echo 'N/A')
AWS CLI Version: $(aws --version 2>/dev/null || echo 'N/A')
Host: $(hostname)
User: $(whoami)

Backup Contents:
- Terraform configuration and state
- Docker configurations
- Scripts and documentation
- Deployment summaries

To restore:
1. Copy terraform/ directory to new location
2. Run 'terraform plan' to verify state
3. Redeploy if needed with 'terraform apply'
EOF
    
    # Compress backup
    tar -czf "${backup_dir}.tar.gz" "$backup_dir"
    rm -rf "$backup_dir"
    
    log_success "Backup created: ${backup_dir}.tar.gz"
    echo "Backup size: $(du -sh "${backup_dir}.tar.gz" | cut -f1)"
    
    return 0
}

# Destroy AWS resources
destroy_aws_resources() {
    log "Destroying AWS resources..."
    
    cd terraform
    
    # Check if state file exists
    if [ ! -f "terraform.tfstate" ]; then
        log_warning "No Terraform state file found. Nothing to destroy."
        cd ..
        return 0
    fi
    
    # Show what will be destroyed
    log "Planning destruction..."
    if ! terraform plan -destroy -out=destroy.tfplan; then
        log_error "Failed to create destruction plan"
        cd ..
        return 1
    fi
    
    # Confirm destruction unless forced
    if [ "$FORCE_DESTROY" = false ] && [ "$CLEANUP_MODE" = "interactive" ]; then
        echo ""
        echo "⚠️  WARNING: This will permanently destroy all AWS resources!"
        echo "All data, configurations, and instances will be lost."
        echo ""
        read -p "Are you sure you want to continue? Type 'yes' to confirm: " -r
        if [ "$REPLY" != "yes" ]; then
            log "Destruction cancelled"
            cd ..
            return 0
        fi
    fi
    
    # Execute destruction
    log "Executing destruction plan..."
    if terraform apply destroy.tfplan; then
        log_success "AWS resources destroyed successfully"
        
        # Clean up plan file
        rm -f destroy.tfplan
        
        # Optionally remove state file
        if [ "$CLEANUP_MODE" = "auto" ] || [ "$FORCE_DESTROY" = true ]; then
            log "Removing Terraform state files..."
            rm -f terraform.tfstate terraform.tfstate.backup
        fi
    else
        log_error "Failed to destroy some resources. Check manually."
        cd ..
        return 1
    fi
    
    cd ..
    return 0
}

# Clean up local files
cleanup_local_files() {
    if [ "$CLEANUP_LOCAL_FILES" = false ]; then
        log "Skipping local file cleanup"
        return 0
    fi
    
    log "Cleaning up local files..."
    
    # Confirm local cleanup
    if [ "$FORCE_DESTROY" = false ] && [ "$CLEANUP_MODE" = "interactive" ]; then
        echo ""
        read -p "Also remove local configuration files? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Skipping local file cleanup"
            return 0
        fi
    fi
    
    # Clean up temporary files
    log "Removing temporary files..."
    rm -f deployment-summary.txt deployment-outputs.txt
    rm -f /tmp/soc_lab_*.log
    rm -rf /tmp/sqli_results /tmp/command_injection_results
    
    # Clean up Docker data
    if [ -d "docker" ]; then
        log "Cleaning up Docker data..."
        cd docker
        if [ -f "docker-compose.yml" ]; then
            docker-compose down --volumes --remove-orphans 2>/dev/null || log_warning "Docker cleanup failed"
        fi
        cd ..
    fi
    
    # Clean up generated files
    log "Removing generated configuration files..."
    find . -name "*.log" -type f -delete 2>/dev/null || true
    find . -name "*.tmp" -type f -delete 2>/dev/null || true
    
    log_success "Local files cleaned up"
}

# Generate cleanup report
generate_cleanup_report() {
    local report_file="cleanup-report-$(date +%Y%m%d_%H%M%S).txt"
    
    log "Generating cleanup report: $report_file"
    
    cat > "$report_file" << EOF
SOC Lab Cleanup Report
======================

Cleanup Details:
---------------
Date/Time: $(date)
Cleanup Mode: $CLEANUP_MODE
Force Destroy: $FORCE_DESTROY
Backup Created: $BACKUP_BEFORE_DESTROY
Local Files Cleaned: $CLEANUP_LOCAL_FILES
Host: $(hostname)
User: $(whoami)

Actions Performed:
-----------------
$(if [ "$BACKUP_BEFORE_DESTROY" = true ]; then echo "✓ Backup created before destruction"; else echo "✗ No backup created"; fi)
$(if [ -f "terraform/terraform.tfstate" ]; then echo "✗ AWS resources may still exist"; else echo "✓ AWS resources destroyed"; fi)
$(if [ "$CLEANUP_LOCAL_FILES" = true ]; then echo "✓ Local files cleaned up"; else echo "✗ Local files preserved"; fi)

Cost Savings:
------------
By destroying the SOC Lab, you've stopped the estimated monthly cost of ~$99 USD.

Next Steps:
----------
1. Verify all AWS resources are destroyed via AWS Console
2. Check for any remaining S3 buckets or snapshots
3. Remove any leftover security groups or VPCs if needed
4. Keep backup file safe if you plan to redeploy later

To Redeploy:
-----------
1. Restore from backup if available
2. Configure terraform.tfvars
3. Run: terraform init && terraform apply
4. Wait for deployment to complete (~10-15 minutes)

Notes:
-----
- All data and configurations have been permanently removed
- Backup files (if created) contain the complete lab configuration
- AWS billing should stop within 24 hours
EOF
    
    log_success "Cleanup report generated: $report_file"
    
    # Display summary
    echo ""
    echo "Cleanup Summary:"
    echo "==============="
    cat "$report_file" | grep -A 20 "Actions Performed:"
}

# Main execution
main() {
    echo ""
    echo "AWS SOC Lab Cleanup Script"
    echo "=========================="
    echo ""
    echo "This script will help you safely destroy your SOC Lab resources."
    echo "Mode: $CLEANUP_MODE"
    echo ""
    
    # Check environment
    if ! check_environment; then
        if [ "$CLEANUP_MODE" != "backup-only" ]; then
            log_warning "No active deployment found, but continuing with local cleanup if requested"
        fi
    fi
    
    # Show current resources
    if [ -f "terraform/terraform.tfstate" ]; then
        show_current_resources
    fi
    
    # Execute based on mode
    case $CLEANUP_MODE in
        backup-only)
            create_backup
            ;;
        interactive|auto)
            create_backup
            
            if [ -f "terraform/terraform.tfstate" ]; then
                destroy_aws_resources
            fi
            
            cleanup_local_files
            ;;
    esac
    
    # Generate report
    generate_cleanup_report
    
    echo ""
    if [ "$CLEANUP_MODE" = "backup-only" ]; then
        log_success "Backup completed successfully"
    else
        log_success "SOC Lab cleanup completed successfully"
        echo "💰 Monthly AWS charges (~$99) should stop within 24 hours"
    fi
    echo "📄 Check cleanup report for details"
    echo ""
}

# Run main function
main "$@"