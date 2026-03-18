# src/phase4_feature_synthesis.py
import os
import json
import gzip
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple
from collections import Counter
import math


@dataclass
class Feature:
    """Đại diện một đặc trưng"""
    value: str
    feature_type: str  # string, hex, api_call, network, registry, etc.
    frequency: float  # Tỷ lệ xuất hiện trong tập mẫu
    samples_count: int
    samples: List[str] = field(default_factory=list)  # List of sample names


class FeatureSynthesizer:
    """Giai đoạn 4: Tổng hợp và so sánh đặc trưng"""
    
    def __init__(self, min_frequency: float = 0.7, dbs_dir: str = None, auto_download: bool = True):
        self.min_frequency = min_frequency
        self.dbs_dir = dbs_dir
        self.whitelist = self._load_whitelist_from_dbs(dbs_dir, auto_download)
    
    def _load_whitelist_from_dbs(self, dbs_dir: str = None, auto_download: bool = True) -> Dict[str, Set[str]]:
        """Load whitelist từ yarGen databases (strings + opcodes)"""
        whitelist = {
            "strings": set(),
            "opcodes": set(),
        }
        
        if dbs_dir is None:
            dbs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dbs")
        
        self.dbs_dir = dbs_dir
        
        # Check and download databases if needed
        if auto_download:
            from .utils.downloader import download_yargen_databases, check_databases
            if not check_databases(dbs_dir):
                print(f"[*] yarGen databases missing. Downloading...")
                if not download_yargen_databases(dbs_dir):
                    print(f"[!] Failed to download databases. Continuing without whitelist.")
        
        if not os.path.exists(dbs_dir):
            print(f"[!] DB directory not found: {dbs_dir}")
            return whitelist
        
        # Load good-strings databases
        import glob
        string_dbs = glob.glob(os.path.join(dbs_dir, "good-strings-part*.db"))
        
        print(f"[*] Loading whitelist from dbs folder...")
        
        if not string_dbs:
            print(f"[!] No whitelist databases found in {dbs_dir}")
            return whitelist
        
        for db_file in string_dbs:
            try:
                with gzip.open(db_file, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
                    whitelist["strings"].update(data.keys())
                    print(f"    Loaded {len(data)} strings from {os.path.basename(db_file)}")
            except Exception as e:
                print(f"    [!] Error loading {db_file}: {e}")
        
        # Load good-opcodes databases
        opcode_dbs = glob.glob(os.path.join(dbs_dir, "good-opcodes-part*.db"))
        
        for db_file in opcode_dbs:
            try:
                with gzip.open(db_file, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
                    whitelist["opcodes"].update(data.keys())
                    print(f"    Loaded {len(data)} opcodes from {os.path.basename(db_file)}")
            except Exception as e:
                print(f"    [!] Error loading {db_file}: {e}")
        
        print(f"[*] Total whitelist: {len(whitelist['strings'])} strings, {len(whitelist['opcodes'])} opcodes")
        return whitelist
    
    def synthesize(self, analyses: List) -> Dict[str, List[Feature]]:
        """Tổng hợp đặc trưng chung từ nhiều phân tích"""
        # Use dict instead of Counter to track samples
        all_features = {
            "strings": {},
            "strings_unicode": {},
            "hex_strings": {},
            "base64_strings": {},
            "reversed_strings": {},
            "imports": {},
            "exports": {},
            "ep_bytes": {},
            "opcodes": {},
        }
        
        total_samples = len(analyses)
        
        # Helper function to get features from either dict or object
        def get_features(static, key):
            if isinstance(static, dict):
                return static.get(key, [])
            else:
                return getattr(static, key, [])
        
        # Get sample names
        sample_names = []
        for a in analyses:
            if isinstance(a, dict):
                sample_names.append(a.get("variant", a.get("file_path", "unknown")))
            elif hasattr(a, "variant"):
                sample_names.append(a.variant)
            else:
                sample_names.append("unknown")
        
        # Đếm tần suất và track samples
        for idx, analysis in enumerate(analyses):
            sample_name = sample_names[idx]
            
            if isinstance(analysis, dict):
                static = analysis.get("static", {})
            else:
                static = analysis.static
            
            # Basic strings
            for s in get_features(static, "strings"):
                if s not in all_features["strings"]:
                    all_features["strings"][s] = {"count": 0, "samples": []}
                all_features["strings"][s]["count"] += 1
                all_features["strings"][s]["samples"].append(sample_name)
            
            # Unicode strings
            for s in get_features(static, "strings_unicode"):
                if s not in all_features["strings_unicode"]:
                    all_features["strings_unicode"][s] = {"count": 0, "samples": []}
                all_features["strings_unicode"][s]["count"] += 1
                all_features["strings_unicode"][s]["samples"].append(sample_name)
            
            # Hex strings
            for s in get_features(static, "hex_strings"):
                if s not in all_features["hex_strings"]:
                    all_features["hex_strings"][s] = {"count": 0, "samples": []}
                all_features["hex_strings"][s]["count"] += 1
                all_features["hex_strings"][s]["samples"].append(sample_name)
            
            # Base64 strings
            for s in get_features(static, "base64_strings"):
                if s not in all_features["base64_strings"]:
                    all_features["base64_strings"][s] = {"count": 0, "samples": []}
                all_features["base64_strings"][s]["count"] += 1
                all_features["base64_strings"][s]["samples"].append(sample_name)
            
            # Reversed strings
            for s in get_features(static, "reversed_strings"):
                if s not in all_features["reversed_strings"]:
                    all_features["reversed_strings"][s] = {"count": 0, "samples": []}
                all_features["reversed_strings"][s]["count"] += 1
                all_features["reversed_strings"][s]["samples"].append(sample_name)
            
            # Imports
            for imp in get_features(static, "imports"):
                if imp not in all_features["imports"]:
                    all_features["imports"][imp] = {"count": 0, "samples": []}
                all_features["imports"][imp]["count"] += 1
                all_features["imports"][imp]["samples"].append(sample_name)
            
            # Exports
            for exp in get_features(static, "exports"):
                if exp not in all_features["exports"]:
                    all_features["exports"][exp] = {"count": 0, "samples": []}
                all_features["exports"][exp]["count"] += 1
                all_features["exports"][exp]["samples"].append(sample_name)
            
            # Entry point bytes
            ep_bytes = get_features(static, "ep_bytes")
            if ep_bytes:
                if ep_bytes not in all_features["ep_bytes"]:
                    all_features["ep_bytes"][ep_bytes] = {"count": 0, "samples": []}
                all_features["ep_bytes"][ep_bytes]["count"] += 1
                all_features["ep_bytes"][ep_bytes]["samples"].append(sample_name)
            
            # Opcodes
            for opcode in get_features(static, "opcodes"):
                if opcode not in all_features["opcodes"]:
                    all_features["opcodes"][opcode] = {"count": 0, "samples": []}
                all_features["opcodes"][opcode]["count"] += 1
                all_features["opcodes"][opcode]["samples"].append(sample_name)
        
        # Convert to Feature objects and filter
        common_features = {}
        
        for feature_type, feature_data in all_features.items():
            common_features[feature_type] = []
            
            for value, data in feature_data.items():
                count = data["count"]
                samples = data["samples"]
                frequency = count / total_samples
                
                # Bỏ qua nếu dưới ngưỡng
                if frequency < self.min_frequency:
                    continue
                
                # Bỏ qua nếu trong whitelist
                if self._is_whitelisted(value, feature_type):
                    continue
                
                feature = Feature(
                    value=value,
                    feature_type=feature_type,
                    frequency=frequency,
                    samples_count=count,
                    samples=samples
                )
                common_features[feature_type].append(feature)
            
            # Sắp xếp theo tần suất
            common_features[feature_type].sort(key=lambda x: x.frequency, reverse=True)
        
        return common_features
    
    def _is_whitelisted(self, value: str, feature_type: str) -> bool:
        """Kiểm tra feature có trong whitelist từ thư mục dbs không"""
        value_lower = value.lower()
        
        if feature_type == "opcodes":
            whitelist_set = self.whitelist.get("opcodes", set())
            if value in whitelist_set:
                return True
        else:
            whitelist_set = self.whitelist.get("strings", set())
            if value in whitelist_set:
                return True
            
            if value_lower in whitelist_set:
                return True
        
        return False
