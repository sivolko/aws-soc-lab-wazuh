# AWS SOC Lab with Wazuh SIEM

🛡️ **A comprehensive, cloud-based Security Operations Center (SOC) training environment built on AWS with Wazuh SIEM for hands-on cybersecurity education and red team/blue team exercises.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Terraform](https://img.shields.io/badge/Terraform-1.0%2B-623CE4?logo=terraform)](https://terraform.io)
[![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?logo=amazon-aws)](https://aws.amazon.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.0-blue?logo=wazuh)](https://wazuh.com)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker)](https://docker.com)

---

## 🎯 Project Overview

The AWS SOC Lab provides a realistic, scalable cybersecurity training environment that combines:

- **🔍 Real-time SIEM monitoring** with Wazuh
- **🎯 Vulnerable applications** for hands-on penetration testing  
- **🏗️ Enterprise-grade infrastructure** on AWS
- **📊 Comprehensive logging and alerting**
- **🔴 Red team attack scenarios** with Kali Linux
- **🔵 Blue team defense exercises** with incident response

Perfect for cybersecurity students, professionals, and organizations looking to enhance their security operations capabilities.

---

## 🏗️ Architecture

```

                    ┌─────────────────────────┐
                    │       Internet          │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │      Jump Box           │
                    │    (Bastion Host)       │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │          AWS VPC (10.0.0.0/16)                │
        │                                               │
        │   ┌─────────────┐         ┌─────────────────┐ │
        │   │ Kali Linux  │◄───────►│   Wazuh SIEM    │ │
        │   │ (Attacker)  │         │ - Manager       │ │
        │   │             │         │ - Indexer       │ │
        │   └─────────────┘         │ - Dashboard     │ │
        │                           └─────────────────┘ │
        │                               │               │
        │                               ▼               │
        │   ┌─────────────┐         ┌─────────────────┐ │
        │   │   Linux     │         │    Windows      │ │
        │   │  Endpoint   │◄───────►│   Endpoint      │ │
        │   │  + DVWA     │         │ + Wazuh Agent   │ │
        │   │  + WebGoat  │         │ + Sysmon        │ │
        │   │ + Juice Shop│         │ + PowerShell    │ │
        │   └─────────────┘         └─────────────────┘ │
        └───────────────────────────────────────────────┘
       
```

## ✨ Features

### 🛡️ Security Operations Center (SOC)
- **Wazuh SIEM Platform**: Full-featured SIEM with real-time monitoring
- **Custom Detection Rules**: MITRE ATT&CK framework-based detection
- **Incident Response**: Automated alerting and response capabilities
- **Compliance Monitoring**: PCI-DSS, NIST, GDPR compliance checks

### 🎯 Vulnerable Applications
- **DVWA**: Damn Vulnerable Web Application for web security testing
- **WebGoat**: OWASP web application security training platform
- **OWASP Juice Shop**: Modern insecure web application
- **Custom Scenarios**: Real-world attack simulations

### 🔴 Red Team Capabilities
- **Kali Linux Platform**: Pre-configured penetration testing environment
- **Attack Scenarios**: SQL injection, XSS, command injection, and more
- **Network Attacks**: Port scanning, brute force, man-in-the-middle
- **Advanced Techniques**: APT simulation, credential dumping, lateral movement

### 🔵 Blue Team Training
- **Real-time Monitoring**: Live attack detection and analysis
- **Forensic Analysis**: Log analysis and incident investigation
- **Threat Hunting**: Proactive threat detection techniques
- **Response Procedures**: Structured incident response workflows

### ☁️ Cloud-Native Architecture
- **AWS Infrastructure**: Scalable, resilient cloud deployment
- **Infrastructure as Code**: Terraform-based automated deployment
- **Cost-Optimized**: Efficient resource utilization (~$119/month)
- **Multi-AZ Support**: High availability and disaster recovery

---

## 🚀 Quick Start

### Prerequisites

- AWS account with admin permissions
- Terraform 1.0+ installed
- AWS CLI configured
- Docker and Docker Compose
- SSH client

### 1. Clone Repository

```bash
git clone https://github.com/sivolko/aws-soc-lab-wazuh.git
cd aws-soc-lab-wazuh
```

### 2. Configure Variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars  # Configure your settings
```

**Key Variables:**
```hcl
aws_region = "us-east-1"
key_name = "your-aws-key-pair"
allowed_cidr_blocks = ["YOUR_IP/32"]  # Your public IP
```

### 3. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan

# Apply configuration
terraform apply
```

### 4. Access Your Lab

```bash
# Get connection details  
terraform output

# Access Wazuh Dashboard
# URL: https://wazuh-server-ip:443
# Username: admin / Password: (from output)

# Connect to Kali Linux
ssh -i your-key.pem kali@kali-ip
```

### ⏱️ Deployment Time
- **Infrastructure**: ~15 minutes
- **Service Configuration**: ~10 minutes  
- **Total Setup**: ~25 minutes

---

## 📚 Comprehensive Documentation

### 📖 Setup Guides
1. **[Prerequisites](docs/setup-guides/01-prerequisites.md)** - Required tools and accounts
2. **[AWS Infrastructure](docs/setup-guides/02-aws-infrastructure.md)** - Deploy AWS resources
3. **[Wazuh SIEM](docs/setup-guides/03-wazuh-deployment.md)** - Configure SIEM platform
4. **[Endpoint Configuration](docs/setup-guides/04-endpoint-configuration.md)** - Setup monitoring agents

### 🏛️ Architecture Documentation
- **[High-Level Architecture](docs/architecture/high-level-architecture.md)** - Complete system design
- **[Network Architecture](docs/architecture/network-architecture.md)** - Network topology and security
- **[Security Architecture](docs/architecture/security-architecture.md)** - Security controls and monitoring

### 🎯 Training Scenarios
- **[Attack Scenarios](docs/attack-scenarios/)** - Red team penetration testing
- **[Defense Exercises](docs/defense-exercises/)** - Blue team incident response
- **[Compliance Testing](docs/compliance/)** - Regulatory compliance validation

### 🔧 Advanced Configuration
- **[Custom Rules](docs/advanced/custom-rules.md)** - Create detection rules
- **[API Integration](docs/advanced/api-integration.md)** - Automate SIEM operations
- **[Scaling Guide](docs/advanced/scaling.md)** - Multi-node deployments

---

## 🎓 Learning Objectives

### 🔍 SOC Analyst Skills
- **SIEM Operation**: Master Wazuh dashboard and analysis tools
- **Alert Triage**: Identify and prioritize security incidents
- **Threat Hunting**: Proactive threat detection techniques
- **Incident Response**: Structured response procedures

### 🛡️ Security Engineering
- **Detection Engineering**: Create custom detection rules
- **Log Analysis**: Parse and analyze security logs
- **Threat Intelligence**: Integrate threat feeds and IOCs
- **Automation**: Automate security operations with APIs

### 🔴 Penetration Testing
- **Web Application Security**: Test OWASP Top 10 vulnerabilities
- **Network Security**: Conduct network penetration tests
- **Post-Exploitation**: Lateral movement and persistence
- **Reporting**: Document findings and recommendations

### 🔵 Incident Response
- **Digital Forensics**: Analyze attack artifacts
- **Containment**: Isolate and contain threats
- **Recovery**: Restore systems and operations
- **Lessons Learned**: Improve security posture

---

## 💰 Cost Breakdown

### Monthly Costs (USD)
| Component | Instance Type | Monthly Cost |
|-----------|---------------|--------------|
| Wazuh Server | t3.large | ~$60 |
| Linux Endpoint | t3.micro | ~$8 |
| Windows Endpoint | t3.micro | ~$8 |
| Kali Attacker | t3.small | ~$15 |
| Jump Box | t3.micro | ~$8 |
| Storage (EBS) | GP3 | ~$15 |
| Data Transfer | Various | ~$5 |
| **Total** | | **~$119/month** |

### 💡 Cost Optimization
- **Spot Instances**: Save 50-70% on compute costs
- **Auto-Shutdown**: Schedule shutdown during non-use hours
- **Reserved Instances**: Long-term savings for continuous use
- **Right-Sizing**: Monitor and optimize instance sizes

---

## 🔧 Components

### Infrastructure
- **AWS VPC**: Isolated network environment
- **EC2 Instances**: Compute resources for all components
- **Security Groups**: Network-level access control
- **IAM Roles**: Fine-grained permission management
- **CloudTrail**: API activity logging
- **CloudWatch**: Monitoring and alerting

### Security Tools
- **Wazuh SIEM**: Open-source security information and event management
- **Kali Linux**: Penetration testing platform
- **Vulnerable Apps**: DVWA, WebGoat, OWASP Juice Shop
- **Sysmon**: Windows system monitoring
- **Filebeat**: Log shipping and forwarding

### Monitoring & Detection
- **Real-time Alerting**: Immediate threat notifications
- **Custom Rules**: MITRE ATT&CK-based detection logic
- **File Integrity Monitoring**: Critical file change detection
- **Behavioral Analysis**: Anomaly detection capabilities
- **Compliance Reporting**: Automated compliance checks

---

## 🎯 Use Cases

### 🎓 **Education & Training**
- Cybersecurity bootcamps and courses
- University cybersecurity programs
- Professional certification training
- Hands-on security workshops

### 💼 **Enterprise Training**
- SOC analyst onboarding
- Red team/blue team exercises
- Incident response drills
- Security awareness training

### 🔬 **Research & Development**
- Security tool development
- Detection rule research
- Threat hunting methodology
- Academic cybersecurity research

### 🏆 **Capture The Flag (CTF)**
- Security competitions
- Training CTF events
- Skills assessment
- Team building exercises

---

## 🚨 Attack Scenarios Included

### Web Application Attacks
- ✅ SQL Injection (Union, Blind, Time-based)
- ✅ Cross-Site Scripting (Reflected, Stored, DOM)
- ✅ Command Injection
- ✅ File Upload Vulnerabilities
- ✅ Authentication Bypass

### Network Attacks
- ✅ Port Scanning and Enumeration
- ✅ Brute Force Attacks (SSH, Web, FTP)
- ✅ Man-in-the-Middle Attacks
- ✅ ARP Spoofing
- ✅ DNS Manipulation

### System-Level Attacks
- ✅ Privilege Escalation
- ✅ Persistence Mechanisms
- ✅ Credential Dumping
- ✅ Process Injection
- ✅ Rootkit Simulation

### Advanced Persistent Threats (APT)
- ✅ Multi-stage Attack Campaigns
- ✅ Lateral Movement
- ✅ Data Exfiltration
- ✅ Command & Control (C2)
- ✅ Living off the Land Techniques

---

## 📊 Detection Coverage

### MITRE ATT&CK Framework
Our detection rules cover the following tactics:

| Tactic | Techniques Covered | Detection Rules |
|--------|-------------------|-----------------|
| Initial Access | T1190, T1566 | 15+ rules |
| Execution | T1059, T1203 | 20+ rules |
| Persistence | T1053, T1547 | 12+ rules |
| Privilege Escalation | T1055, T1068 | 10+ rules |
| Defense Evasion | T1070, T1027 | 18+ rules |
| Credential Access | T1003, T1110 | 8+ rules |
| Discovery | T1018, T1083 | 12+ rules |
| Lateral Movement | T1021, T1080 | 6+ rules |
| Collection | T1005, T1039 | 5+ rules |
| Exfiltration | T1041, T1048 | 4+ rules |

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! See our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Ways to Contribute
- 🐛 **Bug Reports**: Report issues and vulnerabilities
- ✨ **New Features**: Add new attack scenarios or detection rules
- 📚 **Documentation**: Improve guides and tutorials  
- 🔧 **Infrastructure**: Enhance Terraform configurations
- 🎯 **Scenarios**: Create new training exercises

### Getting Started
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📞 Support & Community

### 🆘 Getting Help
- **GitHub Issues**: [Report bugs or request features](https://github.com/sivolko/aws-soc-lab-wazuh/issues)
- **GitHub Discussions**: [Community Q&A and discussions](https://github.com/sivolko/aws-soc-lab-wazuh/discussions)
- **Documentation**: [Comprehensive setup and usage guides](docs/)

### 🌟 Community
- **Contributors**: See our [contributors page](https://github.com/sivolko/aws-soc-lab-wazuh/graphs/contributors)
- **Star the Project**: Show your support by starring the repository
- **Share**: Help others discover this training resource

### 📧 Contact
- **Project Maintainer**: [@sivolko](https://github.com/sivolko)
- **Security Issues**: Please report via GitHub Security tab
- **General Questions**: Use GitHub Discussions

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses
- **Wazuh**: GPL v2 License
- **DVWA**: GPL v3 License  
- **WebGoat**: Apache License 2.0
- **OWASP Juice Shop**: MIT License

---

## ⚠️ Disclaimer

**Educational Purpose Only**: This project is designed for educational and authorized testing purposes only. 

### Important Notes
- ✅ Only use in authorized environments
- ✅ Ensure proper permissions before deployment
- ✅ Follow responsible disclosure for any findings
- ❌ Do not use techniques against unauthorized systems
- ❌ Respect all applicable laws and regulations

### Security Notice
- Always keep your lab environment isolated
- Regularly update all components for security
- Monitor costs to avoid unexpected charges
- Follow AWS security best practices

---

## 🏆 Recognition

### Awards & Mentions
- Featured in cybersecurity training resources
- Used by universities and training organizations
- Recognized by the open-source security community

### Stats
- ⭐ **GitHub Stars**: Growing community of users
- 🍴 **Forks**: Active development by contributors  
- 📥 **Downloads**: Thousands of deployments worldwide
- 🎓 **Training**: Used in educational institutions globally

---

## 🗺️ Roadmap

### Upcoming Features
- [ ] **Kubernetes Integration**: Container orchestration scenarios
- [ ] **Cloud Security**: AWS-specific attack scenarios
- [ ] **Machine Learning**: AI-based threat detection
- [ ] **Mobile Security**: Mobile application testing
- [ ] **IoT Security**: Internet of Things attack scenarios

### Long-term Vision
- Multi-cloud support (Azure, GCP)
- Advanced threat simulation
- Automated red team operations
- Integration with threat intelligence platforms
- Mobile and API testing capabilities

---

## 📚 Additional Resources

### Documentation
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Training Materials
- [SANS SEC504: Hacker Tools, Techniques, and Incident Handling](https://www.sans.org/cyber-security-courses/hacker-techniques-exploits-incident-handling/)
- [EC-Council CEH: Certified Ethical Hacker](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
- [CompTIA CySA+: Cybersecurity Analyst](https://www.comptia.org/certifications/cybersecurity-analyst)

### Community Resources
- [Cybersecurity & Infrastructure Security Agency (CISA)](https://www.cisa.gov/)
- [National Institute of Standards and Technology (NIST)](https://www.nist.gov/cyberframework)
- [Open Web Application Security Project (OWASP)](https://owasp.org/)

---

<div align="center">

## 🚀 Ready to Start Your SOC Journey?

**[📖 Read the Setup Guide](docs/setup-guides/01-prerequisites.md)** | **[🎯 Explore Attack Scenarios](docs/attack-scenarios/)** | **[🤝 Contribute](CONTRIBUTING.md)**

---

**⭐ Star this project if you find it useful!**

**🔄 Fork and customize for your training needs!**

**🤝 Contribute to make cybersecurity education better!**

---

*Built with ❤️ by Shubhendu for the cybersecurity community to encourage hands-on security education*

</div>
