# TLS Certificate Checker

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

A powerful command-line tool for analyzing and verifying SSL/TLS certificates of domains. This tool provides detailed insights into TLS configurations, certificate status, and real-time security assessments, helping you ensure your domains maintain robust security standards.

## 🚀 Features

- ✅ Comprehensive TLS version and cipher suite analysis
- 📊 Advanced security evaluation and rating system
- ⏰ Certificate expiration monitoring
- 🔍 Alternative DNS names verification
- 💾 JSON export capabilities
- ⚠️ Automated warning system
- 🔒 In-depth certificate validation

## 📋 Prerequisites

- Go 1.21 or higher
- Active internet connection for certificate checking

## 🛠️ Installation

### Using Go

```bash
# Clone the repository
git clone https://github.com/username/tls-certificate-checker.git

# Navigate to the project directory
cd tls-certificate-checker

# Build the project
go build -o tls-checker

# Run the application
./tls-checker
```

## 💻 Usage

1. Launch the application:
```bash
./tls-checker
```

2. Enter the domain for analysis:
```
---------------------------------------------------------
|   SSL/TLS Certificate Checker and Security Analyzer   |
---------------------------------------------------------
Enter Web Address (example: example.com): 
```

3. The tool will display a comprehensive analysis including:
   - Active TLS version
   - Implemented cipher suite
   - Certificate issuer information
   - Validity period
   - Security rating
   - Potential security concerns

4. Results are automatically saved in JSON format in the output directory

## 🔍 Sample Output

```json
{
    "host": "example.com",
    "tls_version": "TLS 1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "issuer": "Let's Encrypt Authority X3",
    "subject": "example.com",
    "valid_from": "2024-01-01T00:00:00Z",
    "valid_until": "2024-03-31T23:59:59Z",
    "dns_names": [
        "example.com",
        "www.example.com"
    ],
    "is_valid": true,
    "days_until_expiration": 80,
    "security_rating": "Excellent",
    "warnings": []
}
```

## 📝 License

This project is distributed under the MIT License. See the `LICENSE` file for more information.

---

**Note**: This tool is designed for security analysis purposes. Always ensure you have proper authorization before scanning domains you don't own.