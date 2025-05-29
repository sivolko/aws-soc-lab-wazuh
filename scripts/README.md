# Automation Scripts

This directory contains automation scripts for deployment, maintenance, and attack simulation.

## Structure

```
scripts/
├── deployment/              # Deployment automation
│   ├── deploy-infrastructure.sh
│   ├── deploy-wazuh.sh
│   ├── configure-endpoints.sh
│   └── validate-deployment.sh
├── attack-simulation/       # Red team automation
│   ├── mitre-attack/       # MITRE ATT&CK scenarios
│   ├── web-attacks/        # Web application attacks
│   ├── network-attacks/    # Network-based attacks
│   └── payload-generation/ # Malware and payload scripts
├── maintenance/            # System maintenance
│   ├── backup.sh          # Backup automation
│   ├── update.sh          # System updates
│   ├── cleanup.sh         # Resource cleanup
│   └── health-check.sh    # Health monitoring
└── utilities/             # Helper utilities
    ├── log-analyzer.sh
    ├── rule-tester.sh
    └── performance-monitor.sh
```

## Deployment Scripts

### Full Deployment
```bash
# Complete lab setup
./deployment/full-deploy.sh
```

### Individual Components
```bash
# Infrastructure only
./deployment/deploy-infrastructure.sh

# Wazuh SIEM only
./deployment/deploy-wazuh.sh

# Configure endpoints
./deployment/configure-endpoints.sh
```

## Attack Simulation

### MITRE ATT&CK Scenarios
```bash
# Run specific technique
./attack-simulation/mitre-attack/T1059.001_powershell.sh

# Full attack chain
./attack-simulation/mitre-attack/apt-simulation.sh
```

### Web Application Attacks
```bash
# OWASP Top 10 simulation
./attack-simulation/web-attacks/owasp-top10.sh

# SQL Injection tests
./attack-simulation/web-attacks/sql-injection.sh
```

## Maintenance Scripts

### Automated Backup
```bash
# Daily backup (add to cron)
./maintenance/backup.sh
```

### System Updates
```bash
# Update all components
./maintenance/update.sh
```

### Health Monitoring
```bash
# Check system health
./maintenance/health-check.sh
```

## Script Usage Guidelines

1. **Make scripts executable**
   ```bash
   chmod +x scripts/**/*.sh
   ```

2. **Check prerequisites**
   - Each script includes prerequisite checks
   - Run with `--check` flag to validate environment

3. **Logging**
   - All scripts log to `/var/log/soc-lab/`
   - Use `--verbose` flag for detailed output

4. **Error handling**
   - Scripts include comprehensive error handling
   - Use `--dry-run` to test without making changes

## Security Considerations

- Scripts validate user permissions
- Sensitive operations require confirmation
- All activities are logged and audited
- API keys and credentials use environment variables

---

🤖 **Automation is Key!**