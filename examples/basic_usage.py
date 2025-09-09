"""
Basic usage example of the API Scanner as a library.

This script demonstrates how to:
1. Create an ApiSniffer instance
2. Start the proxy server
3. Handle captured API calls
4. Save results to a file
"""
import asyncio
import json
from pathlib import Path

from api_scanner import ApiSniffer, start, OUTPUT_FILE

async def main():
    # Create an instance of the API sniffer
    sniffer = ApiSniffer()
    
    # Optional: Add a callback to process captured API calls
    def on_api_call(api_call):
        print(f"\nCaptured API call:")
        print(f"  Method: {api_call.request.method}")
        print(f"  URL: {api_call.request.url}")
        print(f"  Status: {api_call.response.status_code if api_call.response else 'No response'}")
    
    # Start the proxy server
    print(f"Starting API Scanner on http://127.0.0.1:8080")
    print("Configure your application to use this proxy")
    print("Press Ctrl+C to stop the scanner\n")
    
    try:
        # Start the proxy server
        await start(
            sniffer,
            host="127.0.0.1",
            port=8080,
            ssl_verify=False  # Disable SSL verification for testing
        )
    except KeyboardInterrupt:
        print("\nStopping API Scanner...")
    finally:
        # Save captured API calls to a file
        output_file = Path(OUTPUT_FILE)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'api_calls': [call.dict() for call in sniffer.api_calls],
                'total_captured': len(sniffer.api_calls)
            }, f, indent=2)
        
        print(f"\nCaptured {len(sniffer.api_calls)} API calls")
        print(f"Results saved to: {output_file.absolute()}")

if __name__ == "__main__":
    asyncio.run(main())
