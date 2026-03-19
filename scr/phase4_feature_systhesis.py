# src/phase4_feature_synthesis.py
import os
import re
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
    score: float = 0.0  # String scoring (like yarGen)


class FeatureSynthesizer:
    """Giai đoạn 4: Tổng hợp và so sánh đặc trưng"""
    
    # Scoring patterns (like yarGen)
    SCORE_PATTERNS = {
        # Patterns that ADD score (malware indicators)
        'drive_letter': (r'[A-Za-z]:\\', 2),
        'file_extensions': (r'(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.vbs|\.tmp|\.sys|\.ps1|\.hta|\.lnk|\.dll|\.ocx)', 4),
        'system_keywords': (r'(cmd\.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log|kernel32|user32|advapi32|ntdll|msvcrt)', 5),
        'protocol_keywords': (r'(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD|http\.=|https\.=)', 5),
        'connection_keywords': (r'(error|http|closed|fail|version|proxy|socket|connect|listen)', 3),
        'browser_ua': (r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', 5),
        'temp_recycler': (r'(TEMP|Temporary|Appdata|Recycler)', 4),
        'hacktool_keywords': (r'(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|vulnerable|credentials|creds|coded|p0c|Content|host|backdoor|trojan|keylog)', 5),
        'network_keywords': (r'(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection|ip|udp|tcp)', 3),
        'ip_address': (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 5),
        'coded_by': (r'(coded |c0d3d |cr3w\b|Coded by |codedby|created by)', 7),
        'parameters': (r'( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)', 4),
        'directory': (r'([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\[A-Za-z]{1,30}', 4),
        'executable_name': (r'^[^\\]+\.(exe|com|scr|bat|sys)$', 4),
        'all_uppercase': (r'^[A-Z]{6,}$', 2.5),
        'all_lowercase': (r'^[a-z]{6,}$', 2),
        'url_pattern': (r'(%[a-z][:\-,;]|\\\\|http[s]?://)', 2.5),
        'malware_name': (r'(ransomware|locky|cryptolocker|cryptowall|wannacry|petya|notpetya|emotet|trickbot|cobalt|icedid|qakbot)', 10),
        'encryption': (r'(encrypt|decrypt|crypt|aes|rc4|rsa|des|key|cipher|iv|salt)', 5),
        'process_inject': (r'(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|SetWindowsHook|ShellExecute|RunPE|reflectiveload)', 7),
        
        # Patterns that REDUCE score (generic/benign indicators)
        'double_dot': (r'\.\.', -5),
        'multiple_spaces': (r'   ', -5),
        'packer_string': (r'(WinRAR\\SFX|UPX|ZPack|ASPack|Petite)', -4),
        'repeated_zeros': (r'0{10,}', -5),
        'repeated_chars': (r'(.)\1{8,}', -5),
        'certificate': (r'(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)', -4),
        'generic_dos': (r'(This program cannot be run in DOS mode|Microsoft (R) Windows|This application)', -10),
    }
    
    def __init__(self, min_frequency: float = 0.7, dbs_dir: str = None, auto_download: bool = True):
        self.min_frequency = min_frequency
        self.dbs_dir = dbs_dir
        self.whitelist = self._load_whitelist_from_dbs(dbs_dir, auto_download)
    
    def _load_whitelist_from_dbs(self, dbs_dir: str = None, auto_download: bool = True) -> Dict[str, Set[str]]:
        """Load whitelist từ yarGen databases (strings + opcodes + imphashes + exports)"""
        whitelist = {
            "strings": set(),
            "opcodes": set(),
            "imphashes": set(),
            "exports": set(),
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
        
        import glob
        
        print(f"[*] Loading whitelist from dbs folder...")
        
        # Load good-strings databases
        string_dbs = glob.glob(os.path.join(dbs_dir, "good-strings-part*.db"))
        
        if not string_dbs:
            print(f"[!] No strings databases found in {dbs_dir}")
        else:
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
        
        if opcode_dbs:
            for db_file in opcode_dbs:
                try:
                    with gzip.open(db_file, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                        whitelist["opcodes"].update(data.keys())
                        print(f"    Loaded {len(data)} opcodes from {os.path.basename(db_file)}")
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")
        
        # Load good-imphashes databases
        imphash_dbs = glob.glob(os.path.join(dbs_dir, "good-imphashes-part*.db"))
        
        if imphash_dbs:
            for db_file in imphash_dbs:
                try:
                    with gzip.open(db_file, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                        whitelist["imphashes"].update(data.keys())
                        print(f"    Loaded {len(data)} imphashes from {os.path.basename(db_file)}")
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")
        
        # Load good-exports databases
        export_dbs = glob.glob(os.path.join(dbs_dir, "good-exports-part*.db"))
        
        if export_dbs:
            for db_file in export_dbs:
                try:
                    with gzip.open(db_file, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                        whitelist["exports"].update(data.keys())
                        print(f"    Loaded {len(data)} exports from {os.path.basename(db_file)}")
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")
        
        print(f"[*] Total whitelist: {len(whitelist['strings'])} strings, {len(whitelist['opcodes'])} opcodes, {len(whitelist['imphashes'])} imphashes, {len(whitelist['exports'])} exports")
        return whitelist
    
    def _calculate_score(self, value: str, is_whitelisted: bool = False, good_count: int = 0) -> float:
        """
        Calculate string score based on patterns (like yarGen)
        Higher score = more likely to be malware-specific
        """
        score = 0.0
        
        # Base score from whitelist
        if is_whitelisted:
            score = -good_count + 5
        else:
            score = 0
        
        # Apply pattern-based scoring
        for pattern_name, (pattern, points) in self.SCORE_PATTERNS.items():
            if re.search(pattern, value, re.IGNORECASE):
                score += points
        
        # Length bonus for longer strings
        if len(value) > 20:
            score += 1
        if len(value) > 50:
            score += 2
        if len(value) > 100:
            score += 3
        
        return score
    
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
            "imphash": {},
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
            
            # Imphash
            imphash = get_features(static, "imphash")
            if imphash and isinstance(imphash, str):
                if imphash not in all_features["imphash"]:
                    all_features["imphash"][imphash] = {"count": 0, "samples": []}
                all_features["imphash"][imphash]["count"] += 1
                all_features["imphash"][imphash]["samples"].append(sample_name)
            
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
                is_whitelisted = self._is_whitelisted(value, feature_type)
                if is_whitelisted and self.min_frequency >= 0.8:
                    continue
                
                # Calculate score for strings
                score = 0.0
                if feature_type in ["strings", "strings_unicode", "hex_strings", "base64_strings"]:
                    score = self._calculate_score(value, is_whitelisted)
                
                feature = Feature(
                    value=value,
                    feature_type=feature_type,
                    frequency=frequency,
                    samples_count=count,
                    samples=samples,
                    score=score
                )
                common_features[feature_type].append(feature)
            
            # Sắp xếp theo score (nếu có) hoặc frequency
            if any(f.score != 0 for f in common_features[feature_type]):
                common_features[feature_type].sort(key=lambda x: (x.score, x.frequency), reverse=True)
            else:
                common_features[feature_type].sort(key=lambda x: x.frequency, reverse=True)
        
        return common_features
    
    def _is_whitelisted(self, value: str, feature_type: str) -> bool:
        """Kiểm tra feature có trong whitelist từ thư mục dbs không"""
        value_lower = value.lower()
        
        if feature_type == "opcodes":
            whitelist_set = self.whitelist.get("opcodes", set())
            if value in whitelist_set:
                return True
        elif feature_type == "imphashes":
            whitelist_set = self.whitelist.get("imphashes", set())
            if value in whitelist_set:
                return True
            if value_lower in whitelist_set:
                return True
        elif feature_type == "exports":
            whitelist_set = self.whitelist.get("exports", set())
            if value in whitelist_set:
                return True
            if value_lower in whitelist_set:
                return True
        else:
            whitelist_set = self.whitelist.get("strings", set())
            if value in whitelist_set:
                return True
            
            if value_lower in whitelist_set:
                return True
        
        return False
