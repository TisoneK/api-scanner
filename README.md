# API Scanner 🔍

A powerful Python tool for intercepting, analyzing, and documenting API requests using mitmproxy. Perfect for API reverse engineering, testing, and documentation.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🕵️‍♂️ Intercept and log HTTP/HTTPS API requests in real-time
- 📊 Comprehensive API call analysis with timing and status codes
- 💾 Save captured API data to structured JSON format
- 🔄 Support for both JSON and XML request/response bodies
- ⚡ Asynchronous processing for high performance
- 🔍 Filter and search through captured requests
- 🛠️ Programmatic access to captured data
- 🔧 Highly configurable through multiple methods
- 🔒 Supports SSL/TLS interception

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Install from PyPI** (recommended):
   ```bash
   pip install api-scanner
   ```

2. **Or install from source**:
   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/api-scanner.git
   cd api-scanner
   
   # Install in development mode
   pip install -e .
   
   # Or with development dependencies
   pip install -e ".[dev]"
   ```

## 🖥️ Command Line Usage

Start the API scanner with default settings:
```bash
api-scanner
```

### Common Options:

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Host to bind the proxy | `127.0.0.1` |
| `--port` | Port to run the proxy | `8080` |
| `--output` | Output file path | `captured_apis.json` |
| `--no-ssl-verify` | Disable SSL verification | `False` |
| `--log-level` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |

### Examples:

```bash
# Run on a specific port
api-scanner --port 8081

# Save output to a custom file
api-scanner --output my_apis.json

# Disable SSL verification (for testing only)
api-scanner --no-ssl-verify
```

## 📚 Library Usage

Integrate the API scanner directly into your Python projects:

```python
import asyncio
from api_scanner import ApiSniffer, start

async def main():
    # Initialize the sniffer
    sniffer = ApiSniffer()
    
    try:
        # Start the proxy server
        await start(
            sniffer,
            host="127.0.0.1",
            port=8080,
            ssl_verify=True,
            output="api_captures.json"
        )
        
        # Access captured API calls
        for call in sniffer.api_calls:
            print(f"[{call.timestamp}] {call.request.method} {call.request.url} -> {call.response.status_code}")
            
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    finally:
        print(f"Captured {len(sniffer.api_calls)} API calls")

if __name__ == "__main__":
    asyncio.run(main())
```

## ⚙️ Configuration

API Scanner can be configured through multiple methods (in order of priority):

### 1. Command Line Arguments
```bash
api-scanner --host 0.0.0.0 --port 8081 --output custom_output.json
```

### 2. Environment Variables
```bash
export API_SCANNER_HOST=0.0.0.0
export API_SCANNER_PORT=8081
export API_SCANNER_OUTPUT=my_apis.json
export API_SCANNER_SSL_VERIFY=false
export API_SCANNER_LOG_LEVEL=DEBUG
```

### 3. Config File (`config/config.json`)
Create a `config.json` file:
```json
{
  "proxy": {
    "host": "127.0.0.1",
    "port": 8080,
    "ssl_verify": true
  },
  "output": {
    "directory": "output",
    "filename": "captured_apis.json"
  },
  "filters": {
    "excluded_extensions": [".js", ".css", ".png", ".jpg", ".svg"],
    "excluded_paths": ["/static/", "/assets/", "/favicon.ico"],
    "keywords": ["api", "v1", "v2", "graphql", "rest"]
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  }
}
```

## 📊 Output Format

Captured API data is saved in a structured JSON format:

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2025-09-08T12:34:56.789012+03:00",
    "request": {
      "method": "GET",
      "url": "https://api.example.com/v1/users?limit=10",
      "headers": {
        "User-Agent": "python-requests/2.28.1",
        "Accept": "application/json"
      },
      "query_params": {
        "limit": ["10"]
      },
      "body": null
    },
    "response": {
      "status_code": 200,
      "reason": "OK",
      "headers": {
        "Content-Type": "application/json",
        "Content-Length": "1234"
      },
      "body": {
        "users": [
          {"id": 1, "name": "John Doe"},
          {"id": 2, "name": "Jane Smith"}
        ]
      },
      "response_time_ms": 123.45
    },
    "metadata": {
      "content_type": "application/json",
      "is_json": true,
      "is_xml": false
    }
  }
]
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ using Python
- Powered by [mitmproxy](https://mitmproxy.org/)
- Inspired by various API debugging tools
