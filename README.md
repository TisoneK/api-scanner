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
### Basic Usage

```bash
# Basic usage with default settings (http://127.0.0.1:8080)
api-scanner start example.com

# With specific host and port
api-scanner start --host 0.0.0.0 --port 8888 example.com

# Using combined host:port format
api-scanner start --bind 0.0.0.0:8888 example.com
```

### UI Filtering

```bash
# Use ignore_ui setting from config (default: true if not specified)
api-scanner start example.com

# Explicitly ignore UI assets (HTML, CSS, JS, etc.)
api-scanner start --ignore-ui example.com

# Include UI assets in capture
api-scanner start --no-ignore-ui example.com
```

### Output and Logging

```bash
# Save output to a specific file
api-scanner start example.com -o output.json

# Set log level (DEBUG, INFO, WARNING, ERROR)
api-scanner start --log-level DEBUG example.com

# Enable verbose output (same as --log-level DEBUG)
api-scanner start -v example.com
```

### SSL and Security

```bash
# Disable SSL verification (for testing only)
api-scanner start --no-ssl-verify example.com

# Short form
api-scanner start -k example.com
```

### Domain Filtering

#### Basic Usage
```bash
# Capture all traffic (no domain filtering)
api-scanner start

# Explicitly capture all traffic (same as above)
api-scanner start --all

# Single domain (only capture requests to this domain)
api-scanner start example.com

# Multiple domains (space-separated)
api-scanner start example.com api.example.com

# Block specific domains
api-scanner start example.com --block analytics.example.com

# Block multiple domains
api-scanner start example.com --block analytics.example.com ads.example.com

# Block domains from a file (one per line)
api-scanner start example.com --block-file blocked_domains.txt
```

#### Filtering UI Assets

By default, the scanner captures all HTTP responses including HTML pages, images, CSS, and JavaScript files. 

Use the `--ignore-ui` flag to filter out:
- HTML responses (all `text/html` content)
- Common web assets (images, CSS, JavaScript, fonts)
- Other non-API responses

```bash
# Ignore UI assets (HTML pages, images, CSS, JS, etc.)
# Only API responses will be captured
api-scanner start --ignore-ui example.com

# Include all responses including UI assets (default)
# Captures everything - HTML pages, images, CSS, JS, and API responses
api-scanner start --no-ignore-ui example.com

# Example: Capture only API responses from all domains
api-scanner start --ignore-ui
```

**Note:** When `--ignore-ui` is enabled, the scanner will only capture:
- JSON/XML responses
- API-like endpoints (typically containing `/api/` in the path)
- Other non-UI responses

This is useful when you only want to analyze API traffic and exclude web page content.

#### Configuration File Settings

You can also configure UI filtering in `config.json`:

```json
"filters": {
    "ignore_ui": true,
    "excluded_extensions": [
        ".js", ".css", ".png", ".jpg", 
        ".jpeg", ".gif", ".svg", ".ico"
        // ... other extensions
    ],
    "excluded_paths": [
        "/static/", "/assets/", "/images/"
    ]
}
```

- `ignore_ui`: Set to `true` to enable UI filtering (default: `true`)
- `excluded_extensions`: File extensions to exclude when UI filtering is enabled
- `excluded_paths`: URL paths to exclude when UI filtering is enabled

Note: Command-line flags will override these settings.

### Output and Logging
```bash
# Save output to a specific file
api-scanner start -o output.json example.com

# Set log level
api-scanner start --log-level DEBUG example.com

# Enable verbose output (same as --log-level DEBUG)
api-scanner start -v example.com
```

### SSL and Proxy Settings
```bash
# Disable SSL verification (for testing only)
api-scanner start -k example.com

# Custom proxy host and port
api-scanner start -H 0.0.0.0 -p 8888 example.com

# Using host:port format
api-scanner start --bind 0.0.0.0:8888 example.com
```

#### Filter File Format
Example `allowed_domains.txt`:
```
# Comments are allowed
example.com
api.example.com
*.staging.example.com  # Wildcards are supported
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

### Required Configuration Files

You must have both of these files in the `config` directory for the scanner to work:

1. **filter.txt** - Contains API path patterns to include (one per line)
   - Location: `src/api_scanner/config/filter.txt`
   - This file is required and contains the main API path patterns

2. **filter_rules.json** - Contains detailed filtering rules and settings
   - Location: `src/api_scanner/config/filter_rules.json`
   - This file is required and contains additional filtering configurations

### Environment Variables

You can customize the scanner's behavior using these environment variables:

## 📋 Configuration

The scanner can be configured using a config file (`config/config.json`) or environment variables.

### Configuration Options

```json
{
  "proxy": {
    "host": "127.0.0.1",
    "port": 8080,
    "ssl_verify": true
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  },
  "output": {
    "directory": "output",
    "filename": "captured_apis.json",
    "pretty_print": true
  },
  "filters": {
    "ignore_ui": true,
    "allowed_hosts": [],
    "excluded_extensions": [
      ".js", ".css", ".png", ".jpg", ".jpeg", ".gif"
    ],
    "excluded_paths": [
      "/static/", "/assets/", "/images/"
    ]
  }
}
```

### Environment Variables

All configuration options can be overridden with environment variables:

```bash
# Proxy settings
export API_SCANNER_PROXY_HOST=0.0.0.0
export API_SCANNER_PROXY_PORT=8888
export API_SCANNER_SSL_VERIFY=false

# Output settings
export API_SCANNER_OUTPUT_DIRECTORY=./results
export API_SCANNER_OUTPUT_FILENAME=my_apis.json

# Filtering
export API_SCANNER_IGNORE_UI=true
export API_SCANNER_ALLOWED_HOSTS="api.example.com,example.org"

# Logging
export API_SCANNER_LOG_LEVEL=DEBUG
```

### Command Line Arguments

All configuration options can also be set via command line arguments. Run `api-scanner --help` for a complete list.

### filter.txt Format

This file defines which API paths should be captured. Each line should be a URL path pattern.

Example `filter.txt`:
```
# API endpoints
/api/
/v1/
/rest/
/auth/

# Specific endpoints
/user/
/account/
/data/
```

### filter_rules.json

This file contains additional filtering rules and settings. Here's the default structure:

```json
{
  "excluded_extensions": [
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", 
    ".svg", ".ico", ".woff", ".woff2", ".ttf"
  ],
  "excluded_paths": [
    "/static/", "/assets/", "/public/", "/resources/",
    "/images/", "/img/", "/css/", "/js/", "/fonts/"
  ],
  "api_keywords": [
    "api", "v1", "v2", "rest", "graphql", "soap"
  ],
  "content_types": [
    "application/json", 
    "application/xml"
  ],
  "accept_headers": [
    "application/json", 
    "application/xml"
  ]
}
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
