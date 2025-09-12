#!/usr/bin/env python3
"""
Command-line tool for optimizing API capture storage with advanced compression and filtering.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional
from src.api_scanner.storage_optimizer import process_capture_file, CompressionMethod

def parse_ignore_patterns(patterns_str: str) -> List[str]:
    """Parse ignore patterns from a comma-separated string."""
    if not patterns_str:
        return []
    return [p.strip() for p in patterns_str.split(',') if p.strip()]

def format_bytes(size: int) -> str:
    """Format bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0 or unit == 'GB':
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"

def print_stats(stats: dict) -> None:
    """Print optimization statistics in a readable format."""
    print("\n" + "="*60)
    print("Optimization Complete!")
    print("="*60)
    
    # Basic stats
    print(f"\n📊 Basic Statistics")
    print(f"  • Total Requests:      {stats['total_requests']:,}")
    print(f"  • Unique Responses:    {stats['unique_responses']:,}")
    print(f"  • Ignored Requests:    {stats['ignored_requests']:,}")
    
    # Size information
    print(f"\n💾 Size Information")
    print(f"  • Original Size:       {format_bytes(stats['original_size'])}")
    print(f"  • Compressed Size:     {format_bytes(stats['compressed_size'])}")
    print(f"  • Output File Size:    {format_bytes(stats['output_size'])}")
    
    # Ratios
    print(f"\n📈 Compression Ratios")
    print(f"  • Response Deduplication: {stats['total_requests'] / stats['unique_responses']:.1f}x")
    if stats.get('compression_ratio', 0) > 0:
        print(f"  • Response Compression:  {stats['compression_ratio']:.1f}x")
        print(f"  • Overall Reduction:     {stats['original_size'] / (stats['output_size'] or 1):.1f}x")
    
    # Performance
    print(f"\n⚡ Performance")
    print(f"  • Processing Time:     {stats['processing_time']:.2f} seconds")
    print(f"  • Requests/sec:        {stats['total_requests'] / (stats['processing_time'] or 1):.1f}")
    
    # Output file
    print(f"\n💾 Output File")
    print(f"  • Path: {stats['output_file']}")
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Optimize API capture storage with advanced compression and filtering',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('input', help='Input JSON file with captured APIs')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for optimized storage')
    
    # Compression options
    compression_group = parser.add_argument_group('Compression Options')
    compression_group.add_argument('--compress-threshold', type=int, default=1024,
                                 help='Minimum response size in bytes to compress (0 = always compress)')
    compression_group.add_argument('--compression-method', 
                                 choices=['zlib', 'gzip', 'base64', 'none'], 
                                 default='zlib',
                                 help='Compression method to use')
    compression_group.add_argument('--no-minify', action='store_false', dest='minify_json',
                                 help='Disable JSON minification')
    
    # Filtering options
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('--ignore-patterns', 
                            help='Comma-separated list of regex patterns to ignore')
    filter_group.add_argument('--no-default-filters', action='store_true',
                            help='Disable default ignore patterns')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--stats', action='store_true', 
                            help='Show detailed statistics after processing')
    output_group.add_argument('--quiet', action='store_true',
                            help='Suppress all output except errors')
    
    args = parser.parse_args()
    
    # Set default output filename if not provided
    input_path = Path(args.input)
    output_path = args.output or input_path.with_name(f"{input_path.stem}_optimized.json")
    
    # Prepare ignore patterns
    ignore_patterns = []
    if not args.no_default_filters:
        ignore_patterns = None  # Will use defaults
    
    if args.ignore_patterns:
        ignore_patterns = parse_ignore_patterns(args.ignore_patterns)
    
    # Process the file
    try:
        if not args.quiet:
            print(f"🔍 Processing {input_path}...")
            if ignore_patterns is not None:
                print(f"   • Using {len(ignore_patterns)} custom ignore patterns")
            else:
                print("   • Using default ignore patterns")
            print(f"   • Compression: {args.compression_method} (threshold: {args.compress_threshold} bytes)")
            
        stats = process_capture_file(
            input_path=str(input_path),
            output_path=str(output_path),
            compress_threshold=args.compress_threshold,
            compression_method=args.compression_method,
            minify_json=args.minify_json,
            custom_ignore_patterns=ignore_patterns if ignore_patterns is not None else []
        )
        
        if not args.quiet or args.stats:
            if args.stats:
                print_stats(stats)
            else:
                print(f"✅ Optimized storage saved to: {output_path}")
                print(f"   • Reduced {stats['total_requests']:,} requests to {stats['unique_responses']:,} unique responses")
                if stats.get('compression_ratio', 0) > 0:
                    print(f"   • Compression ratio: {stats['compression_ratio']:.1f}x")
                print(f"   • Output size: {format_bytes(stats['output_size'])}")
                
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1
        
    return 0

if __name__ == "__main__":
    main()
