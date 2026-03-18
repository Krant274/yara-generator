# utils/downloader.py
import os
import requests
import gzip
import json
from pathlib import Path

YARGEN_DB_URL = "https://github.com/Neo23x0/yarGen-dbs/releases/download/2020-1"

DATABASE_FILES = [
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
    "good-imphashes-part1.db",
    "good-imphashes-part2.db",
    "good-imphashes-part3.db",
    "good-imphashes-part4.db",
    "good-imphashes-part5.db",
    "good-imphashes-part6.db",
    "good-imphashes-part7.db",
    "good-imphashes-part8.db",
    "good-imphashes-part9.db",
    "good-imphashes-Part10.db",
    "good-imphashes-Part11.db",
    "good-opcodes-part1.db",
    "good-opcodes-part2.db",
    "good-opcodes-part3.db",
    "good-opcodes-part4.db",
    "good-opcodes-part5.db",
    "good-opcodes-part6.db",
    "good-opcodes-part7.db",
    "good-opcodes-part8.db",
    "good-opcodes-part9.db",
    "good-opcodes-Part10.db",
    "good-opcodes-Part11.db",
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
]


def download_yargen_databases(dbs_dir: str, force: bool = False) -> bool:
    """
    Download yarGen whitelist databases if not present.
    Returns True if all databases are available (either existing or downloaded).
    """
    dbs_path = Path(dbs_dir)
    dbs_path.mkdir(parents=True, exist_ok=True)
    
    missing_files = []
    for db_file in DATABASE_FILES:
        db_path = dbs_path / db_file
        if not db_path.exists():
            missing_files.append(db_file)
    
    if not missing_files:
        print(f"[*] yarGen databases already present in {dbs_dir}")
        return True
    
    if force:
        print(f"[*] Downloading {len(missing_files)} yarGen database files...")
    else:
        print(f"[*] Missing {len(missing_files)} database files. Downloading...")
    
    for db_file in missing_files:
        url = f"{YARGEN_DB_URL}/{db_file}"
        db_path = dbs_path / db_file
        
        try:
            print(f"    Downloading: {db_file}...", end=" ", flush=True)
            response = requests.get(url, timeout=120)
            response.raise_for_status()
            
            with open(db_path, 'wb') as f:
                f.write(response.content)
            
            size = len(response.content)
            print(f"OK ({size:,} bytes)")
            
        except requests.RequestException as e:
            print(f"FAILED: {e}")
            if db_path.exists():
                db_path.unlink()
            return False
    
    print(f"[*] Downloaded {len(missing_files)} database files to {dbs_dir}")
    return True


def check_databases(dbs_dir: str) -> bool:
    """Check if all required databases are present."""
    dbs_path = Path(dbs_dir)
    
    for db_file in DATABASE_FILES:
        db_path = dbs_path / db_file
        if not db_path.exists():
            return False
    
    return True
