import json
from collections import defaultdict, namedtuple
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Define a named tuple for API call information
ApiCallInfo = namedtuple('ApiCallInfo', ['index', 'timestamp', 'status_code', 'response_size'])

def parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO format timestamp string to datetime object."""
    try:
        # Remove timezone info if present to handle naive datetime
        if '+' in ts_str or 'Z' in ts_str.upper():
            ts_str = ts_str.split('+')[0].split('Z')[0]
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None

def format_timedelta(delta) -> str:
    """Format timedelta to human-readable string."""
    if not delta:
        return "N/A"
    
    total_seconds = int(delta.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    
    return " ".join(parts)

def analyze_duplicates(api_calls: List[dict]) -> Dict[str, List[ApiCallInfo]]:
    """Analyze API calls and group duplicates by method + URL."""
    api_signatures = defaultdict(list)
    
    for idx, call in enumerate(api_calls):
        try:
            method = call.get('request', {}).get('method', 'UNKNOWN')
            url = call.get('request', {}).get('url', '')
            status_code = call.get('response', {}).get('status_code', 0)
            
            # Calculate response size
            response_size = 0
            if 'response' in call and 'body' in call['response']:
                if isinstance(call['response']['body'], str):
                    response_size = len(call['response']['body'].encode('utf-8'))
                elif isinstance(call['response']['body'], (dict, list)):
                    response_size = len(json.dumps(call['response']['body']).encode('utf-8'))
            
            timestamp = parse_timestamp(call.get('request', {}).get('timestamp', ''))
            
            signature = f"{method} {url}"
            api_signatures[signature].append(ApiCallInfo(
                index=idx,
                timestamp=timestamp,
                status_code=status_code,
                response_size=response_size
            ))
        except Exception as e:
            print(f"Error processing API call at index {idx}: {e}")
    
    return api_signatures

def print_duplicates_report(api_signatures: Dict[str, List[ApiCallInfo]], min_duplicates: int = 2) -> None:
    """Print a detailed report of duplicate API calls."""
    # Filter for endpoints with duplicates
    duplicates = {k: v for k, v in api_signatures.items() if len(v) >= min_duplicates}
    
    if not duplicates:
        print("No duplicate API calls found!")
        return
    
    print(f"\n{'='*80}")
    print(f"DUPLICATE API CALLS REPORT (showing endpoints with {min_duplicates}+ calls)")
    print(f"{'='*80}")
    
    # Sort by number of duplicates (descending)
    sorted_duplicates = sorted(duplicates.items(), key=lambda x: len(x[1]), reverse=True)
    
    for signature, calls in sorted_duplicates:
        method, url = signature.split(' ', 1)
        first_call = min(call.timestamp for call in calls if call.timestamp)
        last_call = max(call.timestamp for call in calls if call.timestamp)
        time_span = last_call - first_call if (first_call and last_call) else None
        
        # Calculate success rate
        success_count = sum(1 for call in calls if 200 <= call.status_code < 300)
        success_rate = (success_count / len(calls)) * 100 if calls else 0
        
        # Calculate average response size
        avg_size = sum(call.response_size for call in calls) / len(calls) if calls else 0
        
        print(f"\n{'*'*80}")
        print(f"{method} {url}")
        print(f"{'*'*80}")
        print(f"Total calls: {len(calls)}")
        print(f"Time span: {format_timedelta(time_span) if time_span else 'N/A'}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"Avg. response size: {avg_size/1024:.2f} KB")
        
        # Show status code distribution
        status_counts = defaultdict(int)
        for call in calls:
            status_counts[call.status_code] += 1
        
        print("\nStatus codes:")
        for code, count in sorted(status_counts.items()):
            print(f"  - {code}: {count} ({count/len(calls):.1%})")
        
        # Show timing information
        if len(calls) > 1 and all(call.timestamp for call in calls):
            sorted_calls = sorted(calls, key=lambda x: x.timestamp)
            intervals = []
            for i in range(1, len(sorted_calls)):
                delta = sorted_calls[i].timestamp - sorted_calls[i-1].timestamp
                intervals.append(delta.total_seconds())
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                print(f"\nAvg. interval between calls: {avg_interval:.2f}s")
                print(f"Min interval: {min(intervals):.2f}s")
                print(f"Max interval: {max(intervals):.2f}s")
        
        # Show first and last call timestamps
        print(f"\nFirst call: {first_call}" if first_call else "")
        print(f"Last call:  {last_call}" if last_call else "")

def find_duplicates(file_path: str, min_duplicates: int = 2) -> None:
    """Find and analyze duplicate API calls in the captured data."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            api_calls = json.load(f)
        
        if not isinstance(api_calls, list):
            print("Error: Expected a JSON array of API calls")
            return
        
        print(f"Analyzing {len(api_calls)} API calls...")
        api_signatures = analyze_duplicates(api_calls)
        print_duplicates_report(api_signatures, min_duplicates)
        
    except json.JSONDecodeError:
        print(f"Error: Could not parse JSON file: {file_path}")
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze duplicate API calls in captured data')
    parser.add_argument('file', nargs='?', default='output/captured_apis.json',
                      help='Path to the captured_apis.json file (default: output/captured_apis.json)')
    parser.add_argument('--min-duplicates', type=int, default=2,
                      help='Minimum number of duplicates to report (default: 2)')
    
    args = parser.parse_args()
    
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
    else:
        find_duplicates(str(file_path), args.min_duplicates)
