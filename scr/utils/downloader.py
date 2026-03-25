#!/usr/bin/env python3
"""
Download yarGen databases from GitHub releases
"""
import os
import sys
import urllib.request

BASE_URL = "https://github.com/Neo23x0/yarGen-dbs/releases/download/2020-1"

# File names exactly as they appear on GitHub (case-sensitive)
FILES = [
    # good-strings (11 parts)
    "good-strings-part1.db",
    "good-strings-part2.db",
    "good-strings-part3.db",
    "good-strings-part4.db",
    "good-strings-part5.db",
    "good-strings-part6.db",
    "good-strings-part7.db",
    "good-strings-part8.db",
    "good-strings-part9.db",
    "good-strings-part10.db",
    "good-strings-part11.db",
    # good-opcodes (11 parts)
    "good-opcodes-part1.db",
    "good-opcodes-part2.db",
    "good-opcodes-part3.db",
    "good-opcodes-part4.db",
    "good-opcodes-part5.db",
    "good-opcodes-part6.db",
    "good-opcodes-part7.db",
    "good-opcodes-part8.db",
    "good-opcodes-part9.db",
    "good-opcodes-part10.db",
    "good-opcodes-part11.db",
    # good-imphashes (11 parts)
    "good-imphashes-part1.db",
    "good-imphashes-part2.db",
    "good-imphashes-part3.db",
    "good-imphashes-part4.db",
    "good-imphashes-part5.db",
    "good-imphashes-part6.db",
    "good-imphashes-part7.db",
    "good-imphashes-part8.db",
    "good-imphashes-part9.db",
    "good-imphashes-part10.db",
    "good-imphashes-part11.db",
    # good-exports (11 parts) - Note: Part10 and Part11 have uppercase P
    "good-exports-part1.db",
    "good-exports-part2.db",
    "good-exports-part3.db",
    "good-exports-part4.db",
    "good-exports-part5.db",
    "good-exports-part6.db",
    "good-exports-part7.db",
    "good-exports-part8.db",
    "good-exports-part9.db",
    "good-exports-Part10.db",
    "good-exports-Part11.db",
]


def download_file(url: str, dest: str) -> bool:
    """Download a single file"""
    try:
        print(f"[*] Downloading: {os.path.basename(dest)}")
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"[!] Error downloading {url}: {e}")
        return False


def download_yargen_databases(dbs_dir: str) -> bool:
    """Download all yarGen databases"""
    os.makedirs(dbs_dir, exist_ok=True)
    
    success_count = 0
    for filename in FILES:
        dest_path = os.path.join(dbs_dir, filename)
        
        # Skip if already exists
        if os.path.exists(dest_path):
            print(f"[*] Already exists: {filename}")
            success_count += 1
            continue
        
        # Download
        url = f"{BASE_URL}/{filename}"
        if download_file(url, dest_path):
            success_count += 1
        else:
            # Try alternate case for Part10/Part11
            if "Part10" in filename:
                alt_filename = filename.replace("Part10", "part10")
                alt_url = f"{BASE_URL}/{alt_filename}"
                if download_file(alt_url, dest_path):
                    success_count += 1
            elif "Part11" in filename:
                alt_filename = filename.replace("Part11", "part11")
                alt_url = f"{BASE_URL}/{alt_filename}"
                if download_file(alt_url, dest_path):
                    success_count += 1
    
    print(f"[*] Downloaded {success_count}/{len(FILES)} files")
    return success_count > 0


def check_databases(dbs_dir: str) -> bool:
    """Check if databases exist"""
    if not os.path.exists(dbs_dir):
        return False
    
    # Check for at least one strings database
    db_files = [f for f in os.listdir(dbs_dir) if f.endswith(".db")]
    return len(db_files) >= 3


if __name__ == "__main__":
    if len(sys.argv) > 1:
        dbs_dir = sys.argv[1]
    else:
        dbs_dir = "./dbs"
    
    print(f"[*] Downloading yarGen databases to: {dbs_dir}")
    download_yargen_databases(dbs_dir)
