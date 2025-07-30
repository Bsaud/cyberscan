# CyberScan Malware Hash Checker

CyberScan is a professional-grade malware detection system that verifies file hashes against an extensive malware database. It offers both manual hash verification and automated file analysis with comprehensive reporting.

## Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation Guide](#installation-guide)
- [Usage Instructions](#usage-instructions)
- [Database Management](#database-management)
- [API Documentation](#api-documentation)
- [Deployment Guide](#deployment-guide)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

### Core Capabilities
- **Dual Scan Modes**
  - Hash verification (MD5/SHA256)
  - File upload with automatic hash calculation
- **Advanced Malware Detection**
  - Cross-references multiple hash types
  - Verifies against SQL database with 100,000+ signatures
- **Comprehensive Reporting**
  - Detailed malware metadata display
  - First seen timestamp
  - File type analysis
  - VirusTotal detection rate
- **User Experience**
  - Tabbed interface
  - Drag-and-drop file upload
  - Real-time scanning feedback
  - Responsive design

### Technical Highlights
- Secure file handling with automatic cleanup
- Quote-aware database querying
- Hash validation with strict regex patterns
- Asynchronous file processing

## Technology Stack

### Backend
| Component       | Technology           |
|-----------------|----------------------|
| Framework       | Flask 2.3            |
| Database        | SQLite3  (built usine malware bazzar database)|
| Hash Algorithms | hashlib (MD5/SHA256)|
| File Handling   | Werkzeug             |

### Frontend
| Component       | Technology           |
|-----------------|----------------------|
| UI Framework    | HTML5/CSS3           |
| Icons           | Font Awesome 6       |
| Fonts           | Roboto Mono, Share Tech Mono |
| Animations      | CSS Keyframes        |

### Development Tools
| Purpose         | Tools                |
|-----------------|----------------------|
| Testing         | pytest               |
| Linting         | flake8               |
| Debugging       | Flask Debug Toolbar  |

## Installation Guide

### Prerequisites
- Python 3.8+
- pip 22.0+
- SQLite 3.35+
- 1024MB disk space (for database)

### Step-by-Step Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cyberscan.git
   cd cyberscan
   python3 app.py
