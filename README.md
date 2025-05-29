# AWS SOC Lab with Wazuh SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-Cloud-orange.svg)](https://aws.amazon.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue.svg)](https://wazuh.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-blue.svg)](https://www.docker.com/)

## 🎯 Project Overview

A comprehensive Security Operations Center (SOC) Lab built on AWS infrastructure featuring Wazuh SIEM for both **defensive** and **offensive** cybersecurity practice. This lab provides hands-on experience with real-world security monitoring, threat detection, incident response, and ethical hacking scenarios.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          AWS VPC                                │
│  ┌────────────────────┐    ┌─────────────────────────────────┐  │
│  │   Public Subnet    │    │        Private Subnet           │  │
│  │                    │    │                                 │  │
│  │  ┌──────────────┐  │    │  ┌─────────────────────────────┐│  │
│  │  │   Jump Box   │  │    │  │      Wazuh SIEM Server     ││  │
│  │  │ (Bastion)    │  │    │  │   (Manager + Indexer +     ││  │
│  │  │              │  │    │  │      Dashboard)             ││  │
│  │  └──────────────┘  │    │  └─────────────────────────────┘│  │
│  │                    │    │                                 │  │
│  │  ┌──────────────┐  │    │  ┌─────────────────────────────┐│  │
│  │  │  Kali Linux  │  │    │  │     Windows Endpoint       ││  │
│  │  │ (Attack Box) │  │    │  │    (Wazuh Agent)           ││  │
│  │  │              │  │    │  └─────────────────────────────┘│  │
│  │  └──────────────┘  │    │                                 │  │
│  │                    │    │  ┌─────────────────────────────┐│  │
│  └────────────────────┘    │  │     Linux Endpoint         ││  │
│                             │  │    (Wazuh Agent)           ││  │
│                             │  └─────────────────────────────┘│  │
│                             └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 🎯 Key Features

### Defensive Capabilities
- **Wazuh SIEM** - Single-node Docker deployment with full stack
- **Real-time Monitoring** - File integrity, log analysis, vulnerability detection
- **Threat Detection** - MITRE ATT&CK framework integration
- **Compliance Monitoring** - PCI-DSS, NIST, GDPR rule sets
- **Incident Response** - Automated response actions and playbooks

### Offensive Capabilities
- **Attack Simulation** - Realistic attack scenarios and techniques
- **Vulnerability Assessment** - Intentionally vulnerable applications
- **Penetration Testing** - Kali Linux with popular security tools
- **Red Team Exercises** - Multi-stage attack campaigns
- **Purple Team Activities** - Combined red/blue team exercises

## 📊 Cost Estimation

| Component | Instance Type | Monthly Cost (USD) |
|-----------|---------------|-------------------|
| Wazuh SIEM Server | t3.large | ~$60 |
| Windows Endpoint | t3.micro | ~$8 |
| Linux Endpoint | t3.micro | ~$8 |
| Kali Attack Box | t3.small | ~$15 |
| Jump Box | t3.micro | ~$8 |
| **Total** | | **~$99/month** |

*Note: Costs can be reduced by using spot instances and auto-stop scripts*

## 🚀 Quick Start

### Prerequisites
- AWS Account with appropriate permissions
- Terraform >= 1.0
- Docker & Docker Compose
- SSH Key Pair for EC2 access

### Deployment Steps
```bash
# 1. Clone the repository
git clone https://github.com/sivolko/aws-soc-lab-wazuh.git
cd aws-soc-lab-wazuh

# 2. Configure AWS credentials
aws configure

# 3. Deploy infrastructure
cd terraform
terraform init
terraform plan
terraform apply

# 4. Deploy Wazuh SIEM
cd ../docker
docker-compose up -d

# 5. Configure endpoints
cd ../scripts
./configure-endpoints.sh
```

## 📁 Repository Structure

```
aws-soc-lab-wazuh/
├── docs/                          # Documentation
│   ├── architecture/              # Architecture diagrams
│   ├── setup-guides/             # Step-by-step setup guides
│   ├── attack-scenarios/         # Red team scenarios
│   └── troubleshooting/          # Common issues and fixes
├── terraform/                    # Infrastructure as Code
│   ├── modules/                  # Reusable Terraform modules
│   ├── environments/             # Environment-specific configs
│   └── variables.tf              # Input variables
├── docker/                       # Container configurations 
│   ├── wazuh/                   # Wazuh SIEM stack
│   ├── docker-compose.yml       # Multi-container setup
│   └── configs/                 # Service configurations
├── scripts/                     # Automation scripts
│   ├── deployment/              # Deployment automation
│   ├── attack-simulation/       # Red team scripts
│   └── maintenance/             # Maintenance scripts
├── configs/                     # Configuration files
│   ├── wazuh/                  # Wazuh rules and configs
│   ├── endpoints/              # Agent configurations
│   └── security-groups/        # Network security rules
├── playbooks/                  # Incident response playbooks
│   ├── detection/              # Detection scenarios
│   ├── response/               # Response procedures
│   └── forensics/              # Digital forensics guides
└── examples/                   # Example configurations
    ├── custom-rules/           # Custom detection rules
    ├── dashboards/             # Custom dashboards
    └── integrations/           # Third-party integrations
```

## 🎓 Learning Objectives

By completing this lab, you will gain hands-on experience with:

### Blue Team Skills
- SIEM deployment and configuration
- Log analysis and correlation
- Threat hunting techniques
- Incident response procedures
- Compliance monitoring and reporting

### Red Team Skills
- Attack simulation and execution
- Evasion techniques
- Post-exploitation activities
- Lateral movement strategies
- Persistence mechanisms

### Purple Team Skills
- Detection rule development
- Attack/defense feedback loops
- Security control validation
- Risk assessment methodologies
- Continuous improvement processes

## 🛡️ Security Considerations

- All components deployed in isolated VPC
- Principle of least privilege applied
- MFA enforcement for admin access
- Encrypted storage and communications
- Regular security updates and patches
- Comprehensive logging and monitoring

## 📈 Supported Attack Scenarios

- **Initial Access**: Phishing, credential stuffing, vulnerability exploitation
- **Execution**: PowerShell, command line, scheduled tasks
- **Persistence**: Registry modifications, scheduled tasks, services
- **Privilege Escalation**: Local exploits, token manipulation
- **Defense Evasion**: AV evasion, log clearing, process injection
- **Credential Access**: Credential dumping, brute force attacks
- **Discovery**: Network/system enumeration, account discovery
- **Lateral Movement**: Remote services, network shares
- **Collection**: Data from local system, network shares
- **Exfiltration**: Data transfer over C2 channels

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This lab is for educational purposes only. Always ensure you have proper authorization before testing security tools and techniques. The authors are not responsible for any misuse of the information provided.

## 📞 Support

- 📧 Create an issue for bug reports or feature requests
- 💬 Join our discussions for Q&A and community support
- 📖 Check the documentation for detailed guides

---

**Happy Hacking! 🔒🎯**