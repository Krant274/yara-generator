# src/phase3_feature_synthesis.py
import gzip
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# Optional imports
try:
    from lxml import etree  # type: ignore
except ImportError:
    etree = None


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

    # Full patterns from yarGen - Scoring patterns for string evaluation
    SCORE_PATTERNS = {
        # REDUCE score (generic/benign indicators)
        "double_dot": (r"\.\.", -5),
        "multiple_spaces": (r"   ", -5),
        "packer_string": (r"(WinRAR\\SFX|UPX|ZPack|ASPack|Petite)", -4),
        "repeated_zeros": (r"0{10,}", -5),
        "repeated_chars": (r"(.)\1{8,}", -5),
        "certificate": (
            r"(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)",
            -4,
        ),
        "generic_dos": (
            r"(This program cannot be run in DOS mode|Microsoft \(R\) Windows|This application)",
            -10,
        ),
        # Extensions - Drive
        "drive_letter": (r"[A-Za-z]:\\", 2),
        # Relevant file extensions
        "file_extensions": (
            r"(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.vbs|\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)",
            4,
        ),
        # System keywords
        "system_keywords": (
            r"(cmd\.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)",
            5,
        ),
        # Protocol Keywords
        "protocol_keywords": (r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", 5),
        # Connection keywords
        "connection_keywords": (r"(error|http|closed|fail|version|proxy)", 3),
        # Browser User Agents
        "browser_ua": (
            r"(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)",
            5,
        ),
        # Temp and Recycler
        "temp_recycler": (r"(TEMP|Temporary|Appdata|Recycler)", 4),
        # Malicious keywords - hacktools
        "hacktool_keywords": (
            r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|vulnerable|credentials|creds|coded|p0c|Content|host)",
            5,
        ),
        # Network keywords
        "network_keywords": (
            r"(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)",
            3,
        ),
        # Drive
        "drive_c_to_z": (r"([C-Zc-z]:\\)", 4),
        # IP Address
        "ip_address": (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            5,
        ),
        # Copyright Owner
        "coded_by": (r"(coded | c0d3d |cr3w\b|Coded by |codedby)", 7),
        # Extension generic
        "extension_generic": (r"\.[a-zA-Z]{3}\b", 3),
        # All upper case
        "all_uppercase": (r"^[A-Z]{6,}$", 2.5),
        # All lower case
        "all_lowercase": (r"^[a-z]{6,}$", 2),
        # All lower with space
        "all_lower_with_space": (r"^[a-z\s]{6,}$", 2),
        # All characters
        "all_proper_case": (r"^[A-Z][a-z]{5,}$", 2),
        # URL
        "url_pattern": (
            r"(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)",
            2.5,
        ),
        # Certificates (reduce score)
        "certificate_generic": (
            r"(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)",
            -4,
        ),
        # Parameters
        "parameters": (r"( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)", 4),
        # Directory
        "directory": (r"([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\", 4),
        # Executable - not in directory
        "executable_name": (r"^[^\\]+\.(exe|com|scr|bat|sys)$", 4),
        # Date placeholders
        "date_placeholder": (r"(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)", 3),
        # Placeholders
        "placeholder": (r"[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]", 3),
        # File system elements
        "filesystem_elements": (
            r"(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)",
            3,
        ),
        # Programming
        "programming": (
            r"(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)",
            3,
        ),
        # Credentials
        "credentials": (
            r"(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|auth|privilege)",
            3,
        ),
        # RATs / Malware
        "rat_malware": (
            r"(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)",
            5,
        ),
        # User profiles
        "user_profiles": (
            r"[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]",
            3,
        ),
        # Words ending with numbers
        "words_with_numbers": (r"^[A-Z][a-z]+[0-9]+$", 1),
        # Spying
        "spying": (r"(implant)", 1),
        # Program Path - not Programs or Windows
        "program_path": (r"^[Cc]:\\\\[^PW]", 3),
        # Special strings
        "special_strings": (r"(\\\\.\\|kernel|.dll|usage|\\DosDevices\\)", 5),
        # File
        "file_generic": (r"^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}", 3),
        # Comment Line / Output Log
        "comment_line": (r"^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )", 4),
        # Output typo / special expression
        "typo_expression": (r"(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)", 4),
        # Base64
        "base64_long": (
            r"^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
            7,
        ),
        # Base64 Executables
        "base64_executable": (
            r"(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)",
            5,
        ),
        # Malicious intent
        "malicious_intent": (
            r"(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|payload|inject|back conn)",
            5,
        ),
        # Privileges
        "privileges": (
            r"(administrator|highest|system|debug|dbg|admin|adm|root) privilege",
            4,
        ),
        # System file/process names
        "system_process": (r"(LSASS|SAM|lsass\.exe|cmd\.exe|LSASRV\.DLL)", 4),
        # System file extensions
        "system_extension": (r"(\.exe|\.dll|\.sys)$", 4),
        # Indicators that string is valid
        "valid_indicator": (r"(^\\\\)", 1),
        # Compiler output directories
        "compiler_dirs": (r"(\\Release\\|\\Debug\\|\\bin|\\sbin)", 2),
        # Special - Malware related strings
        "malware_special": (
            r"(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)",
            4,
        ),
        # Powershell
        "powershell": (
            r"(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net\.Webclient|Invoke[A-Z]|Net\.WebClient|-w hidden |-encoded|encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)",
            4,
        ),
        # WMI
        "wmi": (r"( /c WMIC)", 3),
        # Windows Commands
        "windows_commands": (
            r"( net user | net group |ping |whoami |bitsadmin |rundll32\.exe javascript:|schtasks\.exe /create|/c start )",
            3,
        ),
        # Malware names - high score
        "malware_name": (
            r"(ransomware|locky|cryptolocker|cryptowall|wannacry|petya|notpetya|emotet|trickbot|cobalt|icedid|qakbot|redline|raccoon|asyncrat|remcos|_formbook|poisonivy|keylogger|trojan|backdoor|dropper|loader|stub|keylog|infostealer|spyware|adware)",
            10,
        ),
        # Encryption related
        "encryption": (
            r"(encrypt|decrypt|crypt|aes|rc4|rsa|des|key|cipher|iv|salt|crypto|hash|password|credential|credential|dump|pwdump|lsass)",
            5,
        ),
        # Process injection - high score
        "process_inject": (
            r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|SetWindowsHook|ShellExecute|RunPE|reflectiveload|VirtualAllocEx|CreateRemoteThreadEx|QueueUserApc|RtlCreateUserThread|ZwCreateThread)",
            7,
        ),
    }

    def __init__(self, min_frequency: float = 0.7, auto_download: bool = True):
        self.min_frequency = min_frequency
        self.dbs_dir = "./dbs"  # Fixed directory

        # Check and download databases if needed
        if auto_download:
            try:
                from .utils.downloader import check_databases, download_yargen_databases

                if not check_databases(self.dbs_dir):
                    print(f"[*] yarGen databases missing. Downloading...")
                    if not download_yargen_databases(self.dbs_dir):
                        print(
                            f"[!] Failed to download databases. Continuing without whitelist."
                        )
            except ImportError:
                print(
                    f"[!] Downloader module not found. Please download databases manually."
                )

        self.whitelist = self._load_whitelist_from_dbs(self.dbs_dir)
        self.pestudio_strings = self._load_pestudio_strings()

    def _load_pestudio_strings(self) -> Dict[str, Dict]:
        """Load PEStudio blacklist strings từ 3rdparty/strings.xml"""
        pestudio = {
            "strings": {},  # string -> score
            "av": {},  # antivirus related
            "folder": {},  # special folders
            "os": {},  # OS strings
            "reg": {},  # registry keys
            "guid": {},  # GUIDs
            "sddl": {},  # SDDL strings
            "ext": {},  # file extensions
            "agent": {},  # user agents
            "oid": {},  # object identifiers
            "priv": {},  # privileges
            "regex": {},  # regex patterns
        }

        xml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "3rdparty", "strings.xml"
        )

        if not os.path.exists(xml_path):
            print(f"[*] PEStudio strings.xml not found at {xml_path}")
            return pestudio

        if etree is None:
            print(f"[*] lxml not installed, skipping PEStudio strings")
            return pestudio

        try:
            tree = etree.parse(xml_path)

            # Load strings with score
            for elem in tree.findall(".//string"):
                score = elem.get("score", "0")
                try:
                    score = int(score)
                except:
                    score = 0
                text = elem.text
                if text:
                    pestudio["strings"][text.lower()] = score

            # Load other categories
            for category in [
                "av",
                "folder",
                "os",
                "reg",
                "guid",
                "sddl",
                "ext",
                "agent",
                "oid",
                "priv",
                "regex",
            ]:
                for elem in tree.findall(f".//{category}"):
                    text = elem.text
                    if text:
                        pestudio[category][text.lower()] = 1

            print(
                f"[*] Loaded PEStudio blacklist: {len(pestudio['strings'])} strings, {len(pestudio['av'])} av, {len(pestudio['reg'])} reg, etc."
            )

        except ImportError:
            print("[!] lxml not installed. PEStudio scoring disabled.")
        except Exception as e:
            print(f"[!] Error loading PEStudio strings: {e}")

        return pestudio

    def _get_pestudio_score(self, value: str) -> Tuple[int, str]:
        """Lấy điểm PEStudio cho một string"""
        value_lower = value.lower()

        # Check exact match
        if value_lower in self.pestudio_strings["strings"]:
            return self.pestudio_strings["strings"][value_lower], "string"

        # Check category matches
        for category in [
            "av",
            "reg",
            "folder",
            "os",
            "guid",
            "ext",
            "agent",
            "oid",
            "priv",
            "regex",
        ]:
            for pattern in self.pestudio_strings[category]:
                if pattern in value_lower:
                    return 30, category  # Default high score for category matches

        return 0, ""  # type: ignore[return-value]

    def _load_whitelist_from_dbs(self, dbs_dir: str) -> Dict:
        """Load whitelist từ yarGen databases (strings + opcodes + imphashes + exports)"""
        # Structure: {"strings": set(), "opcodes": set(), ...}
        # Note: Using simple sets for faster lookup (counts are optional)
        whitelist = {
            "strings": set(),
            "opcodes": set(),
            "imphashes": set(),
            "exports": set(),
        }

        if dbs_dir is None:
            dbs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dbs")

        self.dbs_dir = dbs_dir

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
                    with gzip.open(db_file, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                        # Just add keys to set (for fast lookup)
                        whitelist["strings"].update(data.keys())
                        print(
                            f"    Loaded {len(data)} strings from {os.path.basename(db_file)}"
                        )
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")

        # Load good-opcodes databases
        opcode_dbs = glob.glob(os.path.join(dbs_dir, "good-opcodes-part*.db"))

        if opcode_dbs:
            for db_file in opcode_dbs:
                try:
                    with gzip.open(db_file, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                        whitelist["opcodes"].update(data.keys())
                        print(
                            f"    Loaded {len(data)} opcodes from {os.path.basename(db_file)}"
                        )
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")

        # Load good-imphashes databases
        imphash_dbs = glob.glob(os.path.join(dbs_dir, "good-imphashes-part*.db"))

        if imphash_dbs:
            for db_file in imphash_dbs:
                try:
                    with gzip.open(db_file, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                        whitelist["imphashes"].update(data.keys())
                        print(
                            f"    Loaded {len(data)} imphashes from {os.path.basename(db_file)}"
                        )
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")

        # Load good-exports databases
        export_dbs = glob.glob(os.path.join(dbs_dir, "good-exports-part*.db"))

        if export_dbs:
            for db_file in export_dbs:
                try:
                    with gzip.open(db_file, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                        whitelist["exports"].update(data.keys())
                        print(
                            f"    Loaded {len(data)} exports from {os.path.basename(db_file)}"
                        )
                except Exception as e:
                    print(f"    [!] Error loading {db_file}: {e}")

        print(
            f"[*] Total whitelist: {len(whitelist['strings'])} strings, {len(whitelist['opcodes'])} opcodes, {len(whitelist['imphashes'])} imphashes, {len(whitelist['exports'])} exports"
        )
        return whitelist

    def _calculate_score(
        self, value: str, is_whitelisted: bool = False, good_count: int = 0
    ) -> float:
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

        # Apply PEStudio scoring (Blacklist)
        pestudio_score, pestudio_type = self._get_pestudio_score(value)
        if pestudio_score > 0:
            # If whitelisted, reduce the PEStudio score
            if is_whitelisted:
                pestudio_score = pestudio_score - (good_count / 1000.0)
            score += pestudio_score

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

                # Get goodware count for scoring
                good_count = self._get_goodware_count(value, feature_type)

                # Calculate score for strings (theo yarGen: mainly from goodware count + PEStudio)
                score = 0.0
                if feature_type in [
                    "strings",
                    "strings_unicode",
                    "hex_strings",
                    "base64_strings",
                ]:
                    score = self._calculate_score(value, is_whitelisted, good_count)

                feature = Feature(
                    value=value,
                    feature_type=feature_type,
                    frequency=frequency,
                    samples_count=count,
                    samples=samples,
                    score=score,
                )
                common_features[feature_type].append(feature)

            # Sắp xếp theo score (nếu có) hoặc frequency
            if any(f.score != 0 for f in common_features[feature_type]):
                common_features[feature_type].sort(
                    key=lambda x: (x.score, x.frequency), reverse=True
                )
            else:
                common_features[feature_type].sort(
                    key=lambda x: x.frequency, reverse=True
                )

        return common_features

    def _is_whitelisted(self, value: str, feature_type: str) -> bool:
        """Kiểm tra feature có trong whitelist từ thư mục dbs không"""
        value_lower = value.lower()

        if feature_type == "opcodes":
            if value in self.whitelist.get("opcodes", set()):
                return True
        elif feature_type == "imphashes":
            if value in self.whitelist.get("imphashes", set()):
                return True
            if value_lower in self.whitelist.get("imphashes", set()):
                return True
        elif feature_type == "exports":
            if value in self.whitelist.get("exports", set()):
                return True
            if value_lower in self.whitelist.get("exports", set()):
                return True
        else:
            if value in self.whitelist.get("strings", set()):
                return True
            if value_lower in self.whitelist.get("strings", set()):
                return True

        return False

    def _get_goodware_count(self, value: str, feature_type: str) -> int:
        """Lấy số lần xuất hiện trong goodware database"""
        return 0  # Simplified - not using counts for now
