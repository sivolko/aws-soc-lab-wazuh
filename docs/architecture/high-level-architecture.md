# High-Level Architecture

The AWS SOC Lab is designed as a comprehensive cybersecurity training environment that simulates real-world enterprise infrastructure while providing hands-on experience with both defensive and offensive security techniques.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  Internet                                        │
└─────────────────┬───────────────────┬─────────────────────────────────────────────┘
                  │                   │
                  │                   │
    ┌─────────────▼─────────────┐    ┌▼──────────────────────────┐
    │       Jump Box            │    │     Kali Linux            │
    │    (Bastion Host)         │    │   (Attack Platform)       │
    │   - SSH Gateway           │    │   - Penetration Testing   │
    │   - Management Access     │    │   - Red Team Operations   │
    │   - Port Forwarding       │    │   - Attack Simulation     │
    └─────────────┬─────────────┘    └───────────────────────────┘
                  │
                  │
┌─────────────────▼─────────────────────────────────────────────────────────────────┐
│                              AWS VPC (10.0.0.0/16)                               │
│                                                                                   │
│  ┌────────────────────────────┐    ┌─────────────────────────────────────────┐   │
│  │      Public Subnet         │    │           Private Subnet                │   │
│  │     (10.0.1.0/24)          │    │          (10.0.3.0/24)                 │   │
│  │                            │    │                                         │   │
│  │  ┌──────────────────────┐  │    │  ┌─────────────────────────────────────┐│   │
│  │  │    NAT Gateway       │  │    │  │         Wazuh SIEM Server          ││   │
│  │  │                      │  │    │  │  ┌─────────────────────────────────┐││   │
│  │  └──────────────────────┘  │    │  │  │        Docker Stack             │││   │
│  │                            │    │  │  │  - Wazuh Manager                │││   │
│  │  ┌──────────────────────┐  │    │  │  │  - Wazuh Indexer (Elasticsearch)│││   │
│  │  │   Internet Gateway   │  │    │  │  │  - Wazuh Dashboard (Kibana)     │││   │
│  │  │                      │  │    │  │  │  - Filebeat                     │││   │
│  │  └──────────────────────┘  │    │  │  └─────────────────────────────────┘││   │
│  │                            │    │  └─────────────────────────────────────┘│   │
│  └────────────────────────────┘    │                                         │   │
│                                    │  ┌─────────────────────────────────────┐│   │
│                                    │  │       Linux Endpoint               ││   │
│                                    │  │  - Ubuntu 20.04 LTS                ││   │
│                                    │  │  - Wazuh Agent                     ││   │
│                                    │  │  - Vulnerable Web Apps:            ││   │
│                                    │  │    * DVWA                          ││   │
│                                    │  │    * WebGoat                       ││   │
│                                    │  │    * OWASP Juice Shop              ││   │
│                                    │  │  - Apache Web Server               ││   │
│                                    │  │  - Docker Runtime                  ││   │
│                                    │  └─────────────────────────────────────┘│   │
│                                    │                                         │   │
│                                    │  ┌─────────────────────────────────────┐│   │
│                                    │  │      Windows Endpoint              ││   │
│                                    │  │  - Windows Server 2019             ││   │
│                                    │  │  - Wazuh Agent                     ││   │
│                                    │  │  - IIS Web Server                  ││   │
│                                    │  │  - XAMPP Stack                     ││   │
│                                    │  │  - PowerShell Logging              ││   │
│                                    │  │  - Windows Event Logging           ││   │
│                                    │  └─────────────────────────────────────┘│   │
│                                    └─────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Network Infrastructure

**Virtual Private Cloud (VPC)**
- **CIDR Block**: 10.0.0.0/16
- **Subnets**: 
  - Public Subnets: 10.0.1.0/24, 10.0.2.0/24
  - Private Subnets: 10.0.3.0/24, 10.0.4.0/24
- **Availability Zones**: Multi-AZ deployment for resilience
- **Internet Gateway**: Provides internet access for public subnets
- **NAT Gateway**: Enables internet access for private subnets
- **Route Tables**: Separate routing for public and private traffic

### 2. Security Operations Center (SIEM)

**Wazuh SIEM Platform**
- **Architecture**: Single-node Docker deployment
- **Components**:
  - **Wazuh Manager**: Central orchestration and analysis engine
  - **Wazuh Indexer**: Elasticsearch-based data storage and search
  - **Wazuh Dashboard**: Kibana-based visualization and management
  - **Filebeat**: Log shipping and forwarding
- **Capabilities**:
  - Real-time log analysis
  - File integrity monitoring
  - Vulnerability detection
  - Compliance monitoring (PCI-DSS, NIST, GDPR)
  - Active response automation
  - MITRE ATT&CK framework integration

### 3. Monitored Endpoints

**Linux Endpoint (Ubuntu 20.04)**
- **Role**: Web server and application host
- **Services**:
  - Apache HTTP Server
  - Docker containers for vulnerable applications
  - SSH daemon
  - System logging (syslog, auth.log)
- **Vulnerable Applications**:
  - DVWA (Damn Vulnerable Web Application)
  - WebGoat (OWASP security training)
  - OWASP Juice Shop
- **Monitoring**: Wazuh agent with custom rules

**Windows Endpoint (Windows Server 2019)**
- **Role**: Enterprise server simulation
- **Services**:
  - Internet Information Services (IIS)
  - XAMPP web stack
  - PowerShell with enhanced logging
  - Windows Event Logging
- **Security Features**:
  - Windows Defender integration
  - PowerShell script block logging
  - Process creation monitoring
  - Registry change detection
- **Monitoring**: Wazuh agent with Windows-specific rules

### 4. Attack Infrastructure

**Kali Linux Attack Platform**
- **Role**: Red team operations and penetration testing
- **Tools Included**:
  - Metasploit Framework
  - Nmap network scanner
  - Burp Suite web security testing
  - SQLMap injection testing
  - Hydra password cracking
  - Custom attack scripts
- **Capabilities**:
  - Network reconnaissance
  - Web application testing
  - Password attacks
  - Exploitation and post-exploitation
  - Lateral movement simulation

**Jump Box (Bastion Host)**
- **Role**: Secure access gateway
- **Functions**:
  - SSH gateway to private network
  - Port forwarding for web services
  - Administrative access point
  - Session logging and monitoring

### 5. Data Flow Architecture

```
Endpoints → Wazuh Agents → Wazuh Manager → Wazuh Indexer → Wazuh Dashboard
    ↓              ↓              ↓              ↓              ↓
 Log Data    Preprocessing    Analysis &     Data Storage   Visualization
 Generation                  Correlation                   & Alerting
```

**Data Collection Points**:
- System logs (syslog, auth.log, kern.log)
- Application logs (Apache, IIS, custom apps)
- Security logs (Windows Event Log, audit logs)
- Network logs (VPC Flow Logs, firewall logs)
- File integrity monitoring
- Process execution monitoring
- Registry change monitoring (Windows)

### 6. Security Architecture

**Network Security**
- **Security Groups**: Micro-segmentation with least privilege
- **NACLs**: Additional network-level access control
- **VPC Flow Logs**: Network traffic monitoring
- **AWS CloudTrail**: API activity logging

**Access Control**
- **IAM Roles**: Service-specific permissions
- **SSH Key Authentication**: No password-based access
- **MFA**: Multi-factor authentication for critical access
- **Bastion Host**: Controlled access to private resources

**Encryption**
- **EBS Encryption**: All storage encrypted at rest
- **TLS/SSL**: All web traffic encrypted in transit
- **Wazuh Communication**: Encrypted agent-manager communication

### 7. Monitoring and Alerting

**Real-time Monitoring**
- **Wazuh Rules**: Custom detection rules for SOC lab scenarios
- **MITRE ATT&CK Mapping**: Technique-based threat detection
- **Behavioral Analysis**: Anomaly detection and baselining
- **Compliance Monitoring**: Automated compliance checking

**Alerting Mechanisms**
- **Dashboard Alerts**: Real-time visualization of threats
- **Email Notifications**: Critical alert notifications
- **API Integration**: External system integration
- **Active Response**: Automated threat response

## Scalability and Performance

### Resource Allocation

| Component | Instance Type | vCPU | Memory | Storage | Purpose |
|-----------|---------------|------|--------|---------|----------|
| Wazuh Server | t3.large | 2 | 8GB | 150GB | SIEM processing |
| Linux Endpoint | t3.micro | 1 | 1GB | 30GB | Web services |
| Windows Endpoint | t3.micro | 1 | 1GB | 50GB | Enterprise simulation |
| Kali Attacker | t3.small | 1 | 2GB | 40GB | Penetration testing |
| Jump Box | t3.micro | 1 | 1GB | 20GB | Bastion services |

### Performance Considerations

**Wazuh SIEM Optimization**
- **Memory**: 8GB allocated for optimal Elasticsearch performance
- **Storage**: GP3 EBS volumes for balanced performance and cost
- **Network**: Enhanced networking for better throughput
- **Indexing**: Optimized for real-time analysis and historical search

**Endpoint Performance**
- **Minimal Overhead**: Wazuh agents designed for low resource usage
- **Efficient Logging**: Structured logging to reduce storage requirements
- **Network Optimization**: Compressed agent communication

## Disaster Recovery and Backup

### Backup Strategy

**Automated Backups**
- **Wazuh Configuration**: Daily backup of rules, decoders, and settings
- **Index Data**: Automated snapshot creation for Elasticsearch indices
- **Instance Snapshots**: EBS snapshot scheduling for critical instances
- **S3 Storage**: Long-term retention in S3 with lifecycle policies

**Recovery Procedures**
- **Infrastructure**: Terraform state-based infrastructure recreation
- **Data Recovery**: Point-in-time recovery from snapshots
- **Configuration Restoration**: Automated configuration deployment
- **Testing**: Regular disaster recovery testing procedures

### High Availability Options

**Multi-AZ Deployment**
- Cross-availability zone distribution
- Load balancing for critical services
- Automatic failover capabilities
- Data replication across zones

## Cost Optimization

### Current Cost Structure

```
Estimated Monthly Costs:
├── Wazuh Server (t3.large)     $60.00
├── Windows Endpoint (t3.micro)  $8.00
├── Linux Endpoint (t3.micro)    $8.00
├── Kali Attacker (t3.small)    $15.00
├── Jump Box (t3.micro)          $8.00
├── Storage (EBS)               $15.00
├── Data Transfer                $5.00
└── Total                       $119.00
```

### Cost Optimization Strategies

**Immediate Savings**
- **Spot Instances**: 50-70% cost reduction for non-critical workloads
- **Reserved Instances**: 30-60% savings for long-term usage
- **Auto-Shutdown**: Scheduled shutdown during non-use hours
- **Right-Sizing**: Performance monitoring and instance optimization

**Long-term Optimization**
- **Serverless Migration**: Move auxiliary functions to Lambda
- **Container Optimization**: Multi-service containers where appropriate
- **Data Lifecycle**: Automated data archival and deletion policies
- **Resource Monitoring**: Continuous optimization based on usage patterns

## Integration Capabilities

### External System Integration

**SIEM Integration**
- **API Access**: RESTful API for external tool integration
- **Log Forwarding**: Syslog and other standard protocols
- **Webhook Support**: Real-time event notification
- **Custom Connectors**: Python-based integration development

**Threat Intelligence**
- **IOC Feeds**: Integration with threat intelligence platforms
- **Reputation Services**: IP/domain reputation checking
- **MISP Integration**: Malware information sharing platform
- **Custom Feeds**: Support for proprietary threat data

### Development and Testing

**CI/CD Integration**
- **Infrastructure as Code**: Terraform-based deployment
- **Configuration Management**: Ansible/Puppet integration
- **Testing Automation**: Automated security testing pipelines
- **Version Control**: Git-based configuration management

**API Development**
- **Custom Detection Rules**: Programmatic rule management
- **Automation Scripts**: Python/Bash automation frameworks
- **Reporting APIs**: Custom report generation and distribution
- **Integration Testing**: Automated integration testing suites

## Future Enhancements

### Planned Improvements

**Advanced Analytics**
- Machine learning-based anomaly detection
- User and entity behavior analytics (UEBA)
- Advanced persistent threat (APT) detection
- Predictive threat modeling

**Extended Infrastructure**
- Multi-cloud deployment options
- Kubernetes orchestration integration
- Serverless security monitoring
- Edge computing integration

**Enhanced Training Scenarios**
- Advanced persistent threat simulations
- Industrial control system (ICS/SCADA) environments
- Cloud-native security scenarios
- Zero-trust architecture implementation

This architecture provides a comprehensive, scalable, and cost-effective platform for cybersecurity training, combining real-world enterprise patterns with hands-on learning opportunities for both defensive and offensive security techniques.