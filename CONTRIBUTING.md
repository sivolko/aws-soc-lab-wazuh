# Contributing to AWS SOC Lab with Wazuh SIEM

🎉 **Thank you for your interest in contributing!** This project thrives on community contributions, and we welcome all forms of participation.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Templates](#issue-templates)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Recognition](#recognition)

## Code of Conduct

This project adheres to a **Code of Conduct** that we expect all contributors to follow:

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, trolling, or discriminatory comments
- Personal attacks or political discussions
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

## How to Contribute

### Types of Contributions Welcome

🐛 **Bug Reports**
- Found a security vulnerability? See [Security Vulnerabilities](#security-vulnerabilities)
- Found a bug? Open an issue with reproduction steps

✨ **Feature Requests**
- New attack scenarios or techniques
- Additional SIEM rules and detections  
- Infrastructure improvements
- Documentation enhancements

📚 **Documentation**
- Fix typos or improve clarity
- Add new tutorials or guides
- Translate documentation
- Create video tutorials

🔧 **Code Contributions**
- Bug fixes
- New features
- Performance improvements
- Test coverage improvements

🛡️ **Security Contributions**
- New detection rules
- Attack simulation scripts
- Threat hunting queries
- Security hardening improvements

### Getting Started

1. **Fork the Repository**
   ```bash
   # Fork via GitHub UI, then clone your fork
   git clone https://github.com/YOUR_USERNAME/aws-soc-lab-wazuh.git
   cd aws-soc-lab-wazuh
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

3. **Make Changes**
   - Follow our [Development Setup](#development-setup)
   - Write tests if applicable
   - Update documentation

4. **Test Your Changes**
   ```bash
   # Test Terraform configurations
   cd terraform && terraform validate
   
   # Test Docker configurations
   cd docker && docker-compose config
   
   # Test scripts
   shellcheck scripts/**/*.sh
   ```

5. **Submit a Pull Request**
   - Follow our [Pull Request Process](#pull-request-process)

## Development Setup

### Prerequisites

**Required Tools:**
- [Terraform](https://terraform.io) >= 1.0
- [Docker](https://docker.com) & Docker Compose
- [AWS CLI](https://aws.amazon.com/cli/) configured
- [Git](https://git-scm.com/)
- Bash shell (Linux/macOS/WSL)

**Recommended Tools:**
- [VS Code](https://code.visualstudio.com/) with extensions:
  - Terraform
  - Docker
  - ShellCheck
  - YAML
- [pre-commit](https://pre-commit.com/) for automated checks

### Local Development Environment

1. **Clone and Setup**
   ```bash
   git clone https://github.com/sivolko/aws-soc-lab-wazuh.git
   cd aws-soc-lab-wazuh
   
   # Install pre-commit hooks (optional but recommended)
   pre-commit install
   ```

2. **Configure Development Environment**
   ```bash
   # Copy example configuration
   cp terraform/terraform.tfvars.example terraform/terraform.tfvars.dev
   
   # Edit with your development settings
   vim terraform/terraform.tfvars.dev
   ```

3. **Validate Changes**
   ```bash
   # Terraform validation
   cd terraform
   terraform init
   terraform validate
   terraform fmt -check
   
   # Docker validation
   cd ../docker
   docker-compose config
   
   # Script validation
   find scripts/ -name "*.sh" -exec shellcheck {} \;
   ```

### Testing Guidelines

**Infrastructure Testing:**
```bash
# Plan deployment without applying
terraform plan -var-file="terraform.tfvars.dev"

# Use terraform-compliance for policy testing (optional)
pip install terraform-compliance
terraform-compliance -f tests/ -p plans/
```

**Script Testing:**
```bash
# Use shellcheck for shell script linting
shellcheck scripts/**/*.sh

# Test script execution with dry-run flags where available
./scripts/deployment/deploy-full-lab.sh --dry-run
```

**Documentation Testing:**
```bash
# Check markdown links
npm install -g markdown-link-checkind . -name "*.md" -exec markdown-link-check {} \;

# Spell check (optional)
npm install -g cspell
cspell "**/*.md"
```

## Contribution Guidelines

### Coding Standards

**Terraform:**
- Use `terraform fmt` for consistent formatting
- Include variable descriptions and types
- Add outputs for resources that might be referenced
- Use meaningful resource names
- Include appropriate tags on all resources

**Shell Scripts:**
- Use `#!/bin/bash` shebang
- Include error handling with `set -e`
- Add usage functions and help text
- Use meaningful variable names
- Include logging and progress indicators

**Docker:**
- Use official base images when possible
- Minimize layer count and image size
- Include health checks
- Use build args for customization
- Follow security best practices

**Documentation:**
- Use clear, concise language
- Include examples and code snippets
- Add table of contents for long documents
- Use consistent heading structure
- Include troubleshooting sections

### Commit Message Format

Use [Conventional Commits](https://conventionalcommits.org/) format:

```
type(scope): brief description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Maintenance tasks

**Examples:**
```
feat(terraform): add support for spot instances

fix(docker): resolve wazuh container startup issue

docs(setup): improve prerequisites documentation

chore(scripts): update health check timeouts
```

### Branch Naming

Use descriptive branch names:

```
feature/add-vulnerability-scanner
fix/docker-compose-startup-issue
docs/improve-setup-guide
refactor/terraform-module-structure
```

## Pull Request Process

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests pass locally
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated (if applicable)
- [ ] No merge conflicts with main branch

### PR Template

Your pull request should include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other: ___________

## Testing
- [ ] Local testing completed
- [ ] New tests added (if applicable)
- [ ] All tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)

## Screenshots (if applicable)
[Add screenshots for UI changes]

## Additional Notes
[Any additional information, concerns, or context]
```

### Review Process

1. **Automated Checks**
   - GitHub Actions will run automated tests
   - All checks must pass before review

2. **Code Review**
   - At least one maintainer review required
   - Address all feedback before merging
   - Maintain respectful discussion

3. **Testing**
   - Reviewers may test changes in their environment
   - Provide clear testing instructions

4. **Merge**
   - Squash and merge for clean history
   - Delete feature branch after merge

## Issue Templates

### Bug Reports

**Title:** Clear, specific description of the bug

**Template:**
```markdown
## Bug Description
A clear description of what the bug is.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- OS: [e.g., Ubuntu 20.04]
- Terraform Version: [e.g., 1.5.0]
- AWS CLI Version: [e.g., 2.13.0]
- Docker Version: [e.g., 24.0.5]

## Additional Context
Add any other context about the problem here.

## Logs
```
[Paste relevant logs here]
```
```

### Feature Requests

**Title:** Brief description of the feature

**Template:**
```markdown
## Feature Description
A clear description of what you want to happen.

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
Describe the solution you'd like.

## Alternatives Considered
Describe any alternative solutions you've considered.

## Additional Context
Add any other context, screenshots, or examples.

## Implementation Notes
[Optional: technical details, constraints, or suggestions]
```

### Security Vulnerabilities

**⚠️ Do NOT create public issues for security vulnerabilities!**

Instead:
1. Email: [security contact - to be added]
2. Use GitHub's private vulnerability reporting
3. Include detailed reproduction steps
4. Allow reasonable time for response

## Recognition

### Contributors

All contributors are recognized in:
- GitHub contributors page
- CONTRIBUTORS.md file
- Release notes for significant contributions

### Contribution Types

We recognize various types of contributions:
- 💻 Code contributions
- 📖 Documentation
- 🐛 Bug reports
- 💡 Ideas and feature requests
- 🎨 Design and UX
- 📢 Community and outreach
- 🚇 Infrastructure and DevOps
- 🔍 Security research

### Special Recognition

**Core Contributors:**  
Regular contributors may be invited to become core contributors with additional privileges.

**Security Researchers:**  
Reported security vulnerabilities are acknowledged in our security advisories.

**Community Champions:**  
Active community members who help others are recognized in project communications.

## Questions and Support

**Have Questions?**
- 💬 GitHub Discussions for general questions
- 🐛 GitHub Issues for bugs and feature requests
- 📧 Email maintainers for private matters

**Getting Help:**
- Check existing documentation first
- Search existing issues and discussions
- Provide detailed information when asking for help
- Be patient and respectful

## Development Resources

**Useful Links:**
- [Terraform Documentation](https://terraform.io/docs)
- [Docker Documentation](https://docs.docker.com/)
- [AWS Documentation](https://docs.aws.amazon.com/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

**Community:**
- [GitHub Discussions](https://github.com/sivolko/aws-soc-lab-wazuh/discussions)
- [Issue Tracker](https://github.com/sivolko/aws-soc-lab-wazuh/issues)

---

**Thank you for contributing to the AWS SOC Lab project!** 🙏

Your contributions help create better cybersecurity training resources for the community. Every contribution, no matter how small, makes a difference.

*Happy Contributing!* 🚀