# API Scanner 🔍

A powerful Python tool for intercepting, analyzing, and documenting API requests using mitmproxy. Perfect for API reverse engineering, testing, and documentation.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/api-scanner)](https://pypi.org/project/api-scanner/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ✨ Features

- 🕵️‍♂️ Intercept and log HTTP/HTTPS API requests in real-time
- 📊 Comprehensive API call analysis with timing and status codes
- 💾 Save captured API data to structured JSON format
- 🔄 Built-in storage optimization to reduce file size
- ⚡ Asynchronous processing for high performance
- 🔍 Filter and search through captured requests
- 🛠️ Programmatic access to captured data
- 🔧 Highly configurable through CLI and config files
- 🔒 Supports SSL/TLS interception
- 📦 Lightweight and easy to integrate

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/TisoneK/api-scanner.git
   cd api-scanner
   ```

2. **Set up a virtual environment** (recommended):
   ```bash
   # Create virtual environment
   python -m venv .venv
   
   # Activate virtual environment
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install in development mode**:
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify the installation**:
   ```bash
   # Using the installed command (recommended for normal use)
   api-scanner --help
   api-scanner --version
   
   # Or using the Python module directly (useful for development)
   python -m api_scanner.cli --help
   python -m api_scanner.cli --version
   
   # Run tests
   pytest
   ```

### Running the Scanner

To start the scanner, use:

```bash
# Basic usage with default settings (http://127.0.0.1:8080)
api-scanner start example.com

# Specify host and port (short form)
api-scanner start -H 0.0.0.0 -p 8888 example.com

# Specify host and port (long form)
api-scanner start --host 0.0.0.0 --port 8888 example.com

# Use combined host:port format
api-scanner start --bind 0.0.0.0:8888 example.com

# Save output to a specific file
api-scanner start example.com -o output.json

# Disable SSL verification (for testing only)
api-scanner start -k example.com
# or
api-scanner start --no-ssl-verify example.com

# Enable verbose logging
api-scanner start -v example.com

# or set specific log level
api-scanner start --log-level DEBUG example.com

# Block specific domains
api-scanner start --block analytics.example.com example.com

# Use a blocklist file
api-scanner start --block-file blocklist.txt example.com

# Filter specific API paths
api-scanner start --filter /api/ example.com
```

For development, you can also run the module directly:
```bash
# Using Python module syntax (useful for debugging)
python -m api_scanner.cli start example.com
```

## 🔄 Storage Optimization

Optimize your captured API data to reduce file size and improve performance:

### Why Optimize?
- **Reduce Storage**: Compress response bodies and remove duplicates
- **Improve Performance**: Faster loading and processing of API data
- **Clean Data**: Filter out noise and focus on relevant requests

### Usage Examples

```bash
# Basic optimization
api-scanner optimize captured.json -o optimized.json

# With gzip compression
api-scanner optimize captured.json --compression-method gzip

# Show optimization statistics
api-scanner optimize captured.json --stats

# Use custom ignore patterns
api-scanner optimize captured.json --ignore-patterns ignore.txt
```

### Ignore Patterns

Create a text file with patterns to exclude from optimization:

```plaintext
# Ignore analytics and telemetry
/analytics/
/telemetry/

# Ignore static assets
\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|eot)(\?.*)?$
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_SCANNER_HOST` | Default proxy host | `127.0.0.1` |
| `API_SCANNER_PORT` | Default proxy port | `8080` |
| `API_SCANNER_OUTPUT` | Default output file | `captured_apis.json` |
| `API_SCANNER_SSL_VERIFY` | Verify SSL certs | `1` |

### Config File

Create `config.ini` in your working directory:

```ini
[api_scanner]
host = 0.0.0.0
port = 8080
output = my_apis.json
ssl_verify = false
log_level = DEBUG
```

## 🛠️ Advanced Usage

### Programmatic Usage

```python
from api_scanner import ApiSniffer

# Create scanner instance
sniffer = ApiSniffer(
    host='0.0.0.0',
    port=8080,
    output='my_apis.json',
    ssl_verify=False
)

# Start capturing
sniffer.start()
```

### Filtering Requests

```python
# Only capture specific paths
sniffer = ApiSniffer(allowed_paths=['/api/v1/'])

# Exclude patterns
sniffer = ApiSniffer(blocked_paths=['/static/'])
```

## 🚀 Development

### Setup

```bash
# Clone repository
git clone https://github.com/TisoneK/api-scanner.git
cd api-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with debug logging
python -m api_scanner -v start example.com
```

### Project Structure

```
api-scanner/
├── src/
│   └── api_scanner/
│       ├── __init__.py
│       ├── cli.py         # Command line interface
│       ├── core.py        # Core functionality
│       ├── utils.py       # Utility functions
│       └── config/        # Configuration handling
├── tests/                # Test files
├── examples/             # Usage examples
├── pyproject.toml        # Project metadata
└── README.md             # This file
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a PR.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ by API Scanner Team
</p>
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
