#!/usr/bin/env python3
"""
YARA Scanner - Detect malware using generated YARA rules

Usage:
    python scan_yar.py <file_or_directory> <rule_file.yar>
    python scan_yar.py <file_or_directory> <rule_file.yar> --json

Examples:
    python scan_yar.py /path/to/suspicious_file output/Wannacry.yar
    python scan_yar.py /path/to/malware_samples output/Wannacry.yar --json
    python scan_yar.py /path/to/malware_samples output/Wannacry.yar --verbose
"""

import os
import sys
import argparse
import json
import yara
from pathlib import Path
from datetime import datetime


def load_rules(rule_path):
    """Load YARA rules from file"""
    try:
        rules = yara.compile(rule_path)
        print(f"[+] Loaded rules from: {rule_path}")
        return rules
    except yara.Error as e:
        print(f"[!] Error loading rules: {e}")
        sys.exit(1)


def scan_file(rules, file_path, verbose=False):
    """Scan a single file with YARA rules"""
    try:
        matches = rules.match(file_path)
        
        result = {
            "file": file_path,
            "is_malware": len(matches) > 0,
            "matches": []
        }
        
        for match in matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if hasattr(match, 'meta') else {}
            }
            result["matches"].append(match_info)
            
            if verbose:
                print(f"  [!] Matched: {match.rule}")
                print(f"      Family: {match.meta.get('family', 'N/A')}")
                print(f"      Type: {match.meta.get('type', 'N/A')}")
                print(f"      Confidence: {match.meta.get('confidence', 'N/A')}")
        
        return result
        
    except Exception as e:
        return {
            "file": file_path,
            "is_malware": False,
            "error": str(e)
        }


def scan_directory(rules, directory, recursive=True, verbose=False):
    """Scan all files in a directory"""
    results = []
    
    path = Path(directory)
    if not path.exists():
        print(f"[!] Directory not found: {directory}")
        return results
    
    # Find all files
    if recursive:
        files = list(path.rglob("*"))
    else:
        files = list(path.glob("*"))
    
    # Filter only files (not directories)
    files = [f for f in files if f.is_file()]
    
    print(f"[*] Scanning {len(files)} files...")
    
    for i, file_path in enumerate(files):
        if (i + 1) % 10 == 0:
            print(f"    Progress: {i+1}/{len(files)}")
        
        result = scan_file(rules, str(file_path), verbose)
        results.append(result)
    
    return results


def print_summary(results):
    """Print scan summary"""
    total = len(results)
    detected = sum(1 for r in results if r.get("is_malware"))
    errors = sum(1 for r in results if "error" in r)
    
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Total files scanned: {total}")
    print(f"Malware detected:    {detected}")
    print(f"Clean files:          {total - detected - errors}")
    print(f"Errors:               {errors}")
    print("="*50)
    
    if detected > 0:
        print("\n[!] DETECTED MALWARE:")
        print("-"*50)
        for r in results:
            if r.get("is_malware"):
                print(f"  {r['file']}")
                for match in r.get("matches", []):
                    print(f"    -> {match['rule']} ({match['meta'].get('family', 'N/A')})")


def main():
    parser = argparse.ArgumentParser(
        description="Scan files/directories with YARA rules to detect malware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("rules", help="YARA rule file (.yar)")
    parser.add_argument("--recursive", "-r", action="store_true", 
                        help="Scan directories recursively")
    parser.add_argument("--json", "-j", action="store_true", 
                        help="Output results in JSON format")
    parser.add_argument("--verbose", "-v", action="store_true", 
                        help="Show detailed match information")
    parser.add_argument("--output", "-o", help="Save results to file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"[!] Target not found: {args.target}")
        sys.exit(1)
    
    if not os.path.exists(args.rules):
        print(f"[!] Rules file not found: {args.rules}")
        sys.exit(1)
    
    print(f"\nYARA Scanner")
    print(f"Target: {args.target}")
    print(f"Rules:  {args.rules}")
    print(f"Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*50)
    
    # Load rules
    rules = load_rules(args.rules)
    
    # Scan
    if os.path.isfile(args.target):
        results = [scan_file(rules, args.target, args.verbose)]
    else:
        results = scan_directory(rules, args.target, args.recursive, args.verbose)
    
    # Output
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_summary(results)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {args.output}")
    
    # Exit with appropriate code
    detected = sum(1 for r in results if r.get("is_malware"))
    sys.exit(0 if detected == 0 else 1)


if __name__ == "__main__":
    main()