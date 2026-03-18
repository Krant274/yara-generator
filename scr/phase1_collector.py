# src/phase1_collector.py
import os
import hashlib
import json
import shutil
from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class MalwareSample:
    file_path: str
    family: str
    variant: str
    md5: str
    sha256: str
    source: str
    collection_date: str
    file_type: str


class MalwareCollector:
    """Giai đoạn 1: Thu thập mẫu malware từ thư mục người dùng cung cấp"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.samples: List[MalwareSample] = []
        os.makedirs(output_dir, exist_ok=True)
    
    def collect_from_directory(self, directory: str, family: str) -> List[MalwareSample]:
        """Thu thập từ thư mục nội bộ (mỗi subdirectory = 1 mẫu malware, tất cả files)"""
        entries = sorted(os.listdir(directory))
        
        for entry in entries:
            subdir_path = os.path.join(directory, entry)
            
            if not os.path.isdir(subdir_path):
                continue
            
            variant_name = entry
            all_files = self._find_all_files(subdir_path)
            
            if not all_files:
                print(f"    Skipping: {variant_name} (no files found)")
                continue
            
            # Copy all files to output directory
            variant_dir = os.path.join(self.output_dir, variant_name)
            os.makedirs(variant_dir, exist_ok=True)
            
            # Use first valid file for primary hash
            main_file = None
            for f in all_files:
                if self._is_valid_malware(f):
                    main_file = f
                    break
            
            if main_file:
                md5, sha256 = self._calculate_hashes(main_file)
                
                for src_file in all_files:
                    filename = os.path.basename(src_file)
                    dest_path = os.path.join(variant_dir, filename)
                    shutil.copy2(src_file, dest_path)
                
                sample = MalwareSample(
                    file_path=variant_dir,
                    family=family,
                    variant=variant_name,
                    md5=md5,
                    sha256=sha256,
                    source="user_provided",
                    collection_date=datetime.now().isoformat(),
                    file_type=self._detect_file_type(main_file)
                )
                self.samples.append(sample)
                print(f"    Found sample: {variant_name} ({len(all_files)} files)")
            else:
                print(f"    Skipping: {variant_name} (no valid files)")
        
        return self.samples
    
    def _find_all_files(self, subdir: str) -> List[str]:
        """Tìm tất cả files trong thư mục"""
        all_files = []
        
        for root, _, files in os.walk(subdir):
            for filename in files:
                file_path = os.path.join(root, filename)
                all_files.append(file_path)
        
        return all_files
    
    def _find_main_file(self, subdir: str) -> str | None:
        """Tìm file chính trong thư mục mẫu"""
        priority_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', 
                        '.xls', '.xlsx', '.doc', '.docm', '.ppt', '.pptm']
        
        for root, _, files in os.walk(subdir):
            for filename in files:
                file_path = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()
                
                if ext in priority_exts:
                    return file_path
            
            if files:
                return os.path.join(root, files[0])
        
        return None
    
    def _is_valid_malware(self, file_path: str) -> bool:
        """Kiểm tra file có phải malware hợp lệ (chấp nhận tất cả các loại file)"""
        if not os.path.isfile(file_path):
            return False
        
        size = os.path.getsize(file_path)
        
        # Chấp nhận tất cả các file có kích thước hợp lý
        return 512 <= size <= 1024 * 1024 * 100
    
    def _calculate_hashes(self, file_path: str) -> tuple:
        """Tính MD5 và SHA256"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)
        
        return md5.hexdigest(), sha256.hexdigest()
    
    def _detect_file_type(self, file_path: str) -> str:
        """Phát hiện loại file"""
        with open(file_path, "rb") as f:
            magic = f.read(2)
            
            if magic == b"MZ":
                pe_offset = int.from_bytes(f.read(4), "little")
                f.seek(pe_offset + 4)
                machine = int.from_bytes(f.read(2), "little")
                return "PE64" if machine == 0x8664 else "PE32"
            
            elif magic == b"\x7fEF":
                return "ELF"
            
            elif magic[:4] == b"\x89PNG":
                return "PNG"
            
            return "unknown"
    
    def save_manifest(self, output_path: str):
        """Lưu manifest của các mẫu đã thu thập"""
        manifest = {
            "family": self.samples[0].family if self.samples else "unknown",
            "collection_date": datetime.now().isoformat(),
            "total_samples": len(self.samples),
            "samples": [
                {
                    "md5": s.md5,
                    "sha256": s.sha256,
                    "variant": s.variant,
                    "source": s.source,
                    "file_type": s.file_type
                }
                for s in self.samples
            ]
        }
        
        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2)
