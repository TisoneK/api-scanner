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
   git clone https://github.com/TisoneK/api-scanner.git
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

By default, running `api-scanner` without targets or filters captures everything (subject to built-in static asset exclusions).

Customize the proxy settings (using both short and long forms):
```bash
# Long form
api-scanner --host 0.0.0.0 --port 8081 --output custom_output.json

# Short form equivalent
api-scanner -H 0.0.0.0 -p 8081 -o custom_output.json
```

Disable SSL verification (for testing only):
```bash
# Long form
api-scanner --no-ssl-verify

# Short form equivalent
api-scanner -k
```

Set log level to debug:
```bash
# Long form
api-scanner --log-level DEBUG

# Short form equivalent
api-scanner -l DEBUG
```

### Command-line Options

| Short | Long | Description |
|-------|------|-------------|
| `-v` | `--version` | Show program's version number and exit |
|  | `--bind HOST:PORT` | Bind address in format host:port (overrides --host/--port) |
| `-H` | `--host` | Proxy host to listen on (default: 127.0.0.1) |
| `-p` | `--port` | Proxy port to listen on (default: 8080) |
| `-k` | `--no-ssl-verify` | Disable SSL certificate verification |
| `-o` | `--output` | Output file path (default: captured_apis.json) |
| `-l` | `--log-level` | Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO) |
|  | `--filter` | Path to custom keyword filter file |
|  | `--allow-host` | Allowlist a host/domain to capture (repeatable) |

### Examples

```bash
# Show version
api-scanner --version
# or
api-scanner -v

# Using separate host and port
api-scanner -H 0.0.0.0 -p 8080

# Using combined host:port format
api-scanner --bind 0.0.0.0:8080

# With all options using short forms
api-scanner -H 0.0.0.0 -p 8080 -o my_apis.json -l DEBUG

# Using host:port with other options
api-scanner --bind 0.0.0.0:8080 -o my_apis.json -l DEBUG
```

### Simple domain allowlist (positional targets)

- Pass domains directly to only capture those:
```bash
api-scanner google.com facebook.com
```

- Or pass a single file path with one domain per line (lines starting with `#` are ignored):
```bash
api-scanner allowed_list.txt
```

- You can also mix with flags:
```bash
api-scanner --filter C:\path\to\filter.txt api.example.com
api-scanner --allow-host auth.example.com domains.lst
```

#### Allowlist Notes

- When you pass domains (via positional args or a file), the scanner captures all non-static requests for those exact hosts. 
  - Example: Allowing `google.com` will capture `https://google.com/api` but not `https://api.google.com` or `https://googleapis.com`
  - For comprehensive coverage, you may need to explicitly list all related domains

- If you need to capture all API traffic (including cross-domain requests), run without allowlist filtering:
  ```bash
  api-scanner
  ```
  Then use `--filter` to narrow down results if needed

- If you pass both an allowlist and `--filter`, the host allowlist takes precedence (filter keywords still apply when no allowlist is provided).

- Note: Future versions will include enhanced domain matching with wildcard support (e.g., `*.google.com`) and related domain detection.

- Output behavior:
  - Without `-o/--output`, results are saved to the default `output/captured_apis.json`
  - With `-o output\myfile.json`, results are saved to that file
  - Re-running appends to the same JSON file by merging lists. Use a new file if you want a clean capture

## 📚 Library Usage

Integrate the API scanner directly into your Python projects:

```python
import asyncio
from api_scanner import ApiSniffer

async def main():
    # Initialize and configure the scanner
    scanner = ApiSniffer(
        host="127.0.0.1",
        port=8080,
        ssl_verify=True,
        output="api_captures.json"
    )
    
    try:
        # Start the proxy server
        print("Starting API Scanner. Press Ctrl+C to stop...")
        await scanner.start()
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Access captured API calls
        for call in scanner.api_calls:
            print(f"[{call.request.timestamp}] {call.request.method} {call.request.url} -> {call.response.status_code if call.response else 'No response'}")
        print(f"\nCaptured {len(scanner.api_calls)} API calls")

if __name__ == "__main__":
    asyncio.run(main())
```

## 🛠️ Configuration Options

Customize the scanner's behavior using command-line arguments or a configuration file.

### 🔍 Configuring API Filters

You can customize which API endpoints are captured by editing the filter configuration file. The scanner includes a default set of common API patterns, but you can easily add your own.

1. **Default Filter Location**:
   ```
   src/api_scanner/config/filter.txt
   ```

2. **Filter File Format**:
   - Each line represents a pattern to match against API endpoints
   - Lines starting with `#` are treated as comments
   - Patterns are matched against the URL path
   - Simple wildcard matching is supported

3. **Example Filter Configuration**:
   ```
   # Common API versioning patterns
   /api/
   /v1/
   
   # Specific endpoints
   /auth/
   /users/
   
   # Wildcard example (matches any path containing 'payment')
   *payment*
   ```

4. **Using a Custom Filter File**:
   ```bash
   api-scanner --filter /path/to/your/custom-filter.txt
   ```

   Or in your Python code:
   ```python
   from api_scanner import ApiSniffer
   import asyncio
   
   async def main():
       # Initialize scanner with custom filter file
       scanner = ApiSniffer(
           host="127.0.0.1",
           port=8080,
           ssl_verify=True,
           output="api_captures.json",
           filter_file='/path/to/your/custom-filter.txt'
       )
       
       try:
           print("Starting API Scanner. Press Ctrl+C to stop...")
           await scanner.start()
       except KeyboardInterrupt:
           print("\nShutting down...")
       finally:
           print(f"Captured {len(scanner.api_calls)} API calls")
   
   if __name__ == "__main__":
       asyncio.run(main())
   ```

5. **Best Practices**:
   - Keep your filter patterns specific to avoid capturing unnecessary traffic
   - Group related endpoints together with comments
   - Test new patterns with the `--verbose` flag to see what's being captured
   - Consider versioning your filter file if you maintain different sets of filters

### 🎯 Capturing everything

If you want to capture all API traffic (again, excluding common static assets), simply run:
```bash
api-scanner
```

## ⚙️ Advanced Configuration

### Environment Variables

You can also configure the scanner using environment variables:

```bash
export API_SCANNER_HOST=0.0.0.0
export API_SCANNER_PORT=8080
export API_SCANNER_SSL_VERIFY=false
export API_SCANNER_OUTPUT=my_captures.json
api-scanner
```

### Configuration File

Create a `config.json` file in your working directory:

```json
{
    "proxy": {
        "host": "0.0.0.0",
        "port": 8080,
        "ssl_verify": false
    },
    "output": {
        "filename": "my_captures.json"
    }
}
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
