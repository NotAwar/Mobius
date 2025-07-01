# Mobius MDM Platform

## 🚀 An Open-Source Device Management Platform

**Mobius MDM** is a powerful device management platform that combines the visibility of osquery with the automation capabilities of Ansible. This platform provides IT and security teams with a unified solution for monitoring and managing thousands of computers across different operating systems.

### ✨ Key Features

- **🔍 Device Visibility**: Real-time insights into device status, configuration, and security posture using osquery
- **⚙️ Configuration Management**: Automated device configuration and policy enforcement using Ansible
- **📊 Centralized Dashboard**: Modern web interface for monitoring and managing your entire mobius
- **🔒 Security Focus**: Built-in security policies and compliance monitoring
- **🌐 Cross-Platform**: Support for Linux, macOS, Windows, and IoT devices
- **📈 Scalable**: Designed to handle thousands of devices efficiently

## What's it for?

Organizations use Mobius MDM for:

- **Device Inventory Management**: Complete visibility into hardware and software across your mobius
- **Security Monitoring**: Real-time security posture assessment and threat detection
- **Configuration Management**: Automated deployment of settings, software, and security policies
- **Compliance Reporting**: Automated compliance checks and detailed reporting
- **Incident Response**: Quick device isolation and remediation capabilities

### Supported Platforms

- **Linux**: Ubuntu, Pop!_OS, Debian, RHEL, CentOS, Fedora
- **macOS**: Intel and Apple Silicon
- **Windows**: 10, 11, Server editions
- **IoT devices**: Linux-based embedded systems
- **Containers**: Docker, Kubernetes environments

## Architecture

### Core Components

1. **Mobius Server**: Central management server with REST API
2. **osquery Agents**: Lightweight agents for data collection and monitoring
3. **Ansible Integration**: Configuration management and automation
4. **Web Dashboard**: React-based frontend for management and monitoring
5. **Database**: MySQL for storing device data and configurations

### How It Works

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Dashboard │────│   Mobius Server  │────│   MySQL DB      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                │
                    ┌───────────┼───────────┐
                    │           │           │
            ┌───────▼────┐ ┌────▼─────┐ ┌──▼──────┐
            │  osquery   │ │ Ansible  │ │  Device │
            │   Agent    │ │ Playbook │ │ Configs │
            └────────────┘ └──────────┘ └─────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 20.18.1+
- Go 1.24.4+
- Ansible 2.9+

### Installation

1. **Clone the repository**

   ```bash
   git clone <your-repo-url>
   cd mobius-main
   ```

2. **Start the development environment**

   ```bash
   docker compose up -d
   ```

3. **Build the Mobius server**

   ```bash
   make build
   ```

4. **Initialize the database**

   ```bash
   ./build/mobius prepare db --dev
   ```

5. **Start the Mobius server**

   ```bash
   ./build/mobius serve --dev
   ```

6. **Access the web interface**
   Open your browser to `http://localhost:8080`

## Portal System

Mobius MDM provides three distinct portal interfaces:

### 🔧 Main Dashboard (`/dashboard`)

Primary administrative interface for IT teams:

- Device inventory and monitoring
- Policy management and enforcement
- Software distribution and updates
- Security compliance monitoring
- Ansible MDM configuration

### ⚙️ Internal Admin Portal (`/internal-portal`)

Advanced system administration (Admin only):

- System health monitoring and statistics
- User and team management
- Backend service configuration
- System audit logs and troubleshooting

### 👤 User Portal (`/user-portal`)

Self-service interface for end users:

- Personal device enrollment and management
- Device status monitoring
- Support request submission
- Download enrollment profiles

### 🧭 Portal Navigation (`/portals`)

Central hub for navigating between portals based on user permissions.

For detailed portal documentation, see [docs/portals.md](docs/portals.md).

### Ansible MDM Setup

1. **Configure your inventory**

   ```bash
   cp ansible-mdm/inventory.example ansible-mdm/inventory
   # Edit the inventory file with your device information
   ```

2. **Run the initial setup playbook**

   ```bash
   cd ansible-mdm
   ansible-playbook -i inventory site.yml
   ```

3. **Monitor devices in the dashboard**
   Your devices will now appear in the Mobius dashboard with full monitoring capabilities.

## Configuration

### Environment Variables

- `MOBIUS_MYSQL_ADDRESS`: Database connection string
- `MOBIUS_SERVER_ADDRESS`: Server bind address
- `MOBIUS_AUTH_JWT_KEY`: JWT signing key
- `ANSIBLE_INVENTORY_PATH`: Path to Ansible inventory
- `ANSIBLE_PLAYBOOK_PATH`: Path to Ansible playbooks

### Ansible Integration

The platform includes pre-built Ansible playbooks for:

- osquery installation and configuration
- Security policy enforcement
- Software deployment
- Monitoring setup
- Compliance scanning

## Dashboard Features

### Device Management

- Real-time device status and health monitoring
- Software inventory and vulnerability tracking
- Remote query execution and troubleshooting
- Automated policy compliance checking

### Ansible Integration

- Execute playbooks on selected devices
- Monitor configuration drift
- Automated remediation workflows
- Custom policy deployment

### Reporting and Analytics

- Comprehensive device inventory reports
- Security posture dashboards
- Compliance status tracking
- Historical trend analysis

## Development

### Building from Source

```bash
# Install dependencies
npm install

# Build frontend
npm run build

# Build backend
make build

# Run tests
make test
npm test
```

### Contributing

We welcome contributions! Please see our [contributing guidelines](docs/Contributing/README.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Attribution**: This project is based on [Mobius Device Management](https://github.com/notawar/mobius) and includes significant modifications for Ansible-based device management.

## Support

- 📖 Documentation: [docs/](docs/)
- 🐛 Bug Reports: [GitHub Issues](../../issues)
- 💬 Discussion: [GitHub Discussions](../../discussions)

In keeping with Mobius's value of openness, [Mobius Device Management's company handbook](https://mobiusmdm.com/handbook/company) is public and open source.  You can read about the [history of Mobius and osquery](https://mobiusmdm.com/handbook/company#history) and our commitment to improving the product.

<!-- > To upgrade from Mobius ≤3.2.0, just follow the upgrading steps for the earliest subsequent major release from this repository (it'll work out of the box until the release of Mobius 5.0). -->

## Is it any good?

Mobius is used in production by IT and security teams with thousands of laptops and servers.  Many deployments support tens of thousands of hosts, and a few large organizations manage deployments as large as 400,000+ hosts.

## Chat

Please join us in [MacAdmins Slack](https://www.macadmins.org/) or in [osquery Slack](https://mobiusmdm.com/slack).

The Mobius community is full of [kind and helpful people](https://mobiusmdm.com/handbook/company#empathy).  Whether or not you are a paying customer, if you need help, just ask.

## Contributing &nbsp; [![Run Tests](https://github.com/notawar/mobius/actions/workflows/test.yml/badge.svg)](https://github.com/notawar/mobius/actions/workflows/test.yml) &nbsp; [![Go Report Card](https://goreportcard.com/badge/github.com/notawar/mobius)](https://goreportcard.com/report/github.com/notawar/mobius) &nbsp; [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5537/badge)](https://bestpractices.coreinfrastructure.org/projects/5537) &nbsp; [![Twitter Follow](https://img.shields.io/twitter/follow/mobiuscli.svg?style=social&maxAge=3600)](https://twitter.com/mobiuscli) &nbsp;

The landscape of cybersecurity and IT is too complex.  Let's open it up.

Contributions are welcome, whether you answer questions on [Slack](https://mobiusmdm.com/slack) / [GitHub](https://github.com/notawar/mobius/issues) / [StackOverflow](https://stackoverflow.com/search?q=osquery) / [LinkedIn](https://linkedin.com/company/mobiusmdm) / [Twitter](https://twitter.com/mobiuscli), improve the documentation or [website](./website), write a tutorial, give a talk at a conference or local meetup, give an [interview on a podcast](https://mobiusmdm.com/podcasts), troubleshoot reported issues, or [submit a patch](https://mobiusmdm.com/docs/contributing/contributing).  The Mobius code of conduct is [on GitHub](https://github.com/notawar/mobius/blob/main/CODE_OF_CONDUCT.md).

<!-- - Great contributions are motivated by real-world use cases or learning.
- Some of the most valuable contributions might not touch any code at all.
- Small, iterative, simple (boring) changes are the easiest to merge. -->

## What's next?

To see what Mobius can do, head over to [mobiusmdm.com](https://mobiusmdm.com) and try it out for yourself, grab time with one of the maintainers to discuss, or visit the docs and roll it out to your organization.

#### Production deployment

Mobius is simple enough to [spin up for yourself](https://mobiusmdm.com/docs/get-started/tutorials-and-guides).  Or you can have us [host it for you](https://mobiusmdm.com/pricing).  Premium features are [available](https://mobiusmdm.com/pricing) either way.

#### Documentation

Complete documentation for Mobius can be found at [https://mobiusmdm.com/docs](https://mobiusmdm.com/docs).

## License

The free version of Mobius is available under the MIT license.  The commercial license is also designed to allow contributions to paid features for users whose employment agreements allow them to contribute to open source projects.  (See LICENSE.md for details.)

> Mobius is built on [osquery](https://github.com/osquery/osquery), [nanoMDM](https://github.com/micromdm/nanomdm), [Nudge](https://github.com/macadmins/nudge), and [swiftDialog](https://github.com/swiftDialog/swiftDialog).
