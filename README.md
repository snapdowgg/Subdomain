# Subdomain Scanner
<img width="338" height="120" alt="image" src="https://github.com/user-attachments/assets/f6fa8e8d-15bc-4df4-b122-6caef2c18269" />

## Overview
A Python-based subdomain enumeration tool that automatically collects subdomains from multiple public intelligence sources. Designed for security professionals and researchers conducting authorized security assessments.

## Features
- Single Target Mode - Scan individual domains with detailed output
- Massive Scanning - Process multiple domains from a list file
- Multiple OSINT Sources - Aggregates data from various public sources:
  - crt.sh Certificate Transparency
  - HackerTarget
  - RapidDNS
  - AlienVault OTX
  - URLScan.io
  - Anubis
- Intelligent Processing - Automatic duplicate filtering and data normalization
- Real-time Output - Live subdomain discovery as results come in
- Multi-threaded - Faster scanning with concurrent requests
- Flexible Output - Save results to custom output files

## Requirements
- Python 3.9 or higher
- Required packages:
  - requests
  - urllib3

## Installation

```bash
# Clone the repository
git clone https://github.com/snapdowgg/Subdomain

# Navigate to the directory
cd Subdomain
