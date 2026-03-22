# src/phase6_yara_generator.py
import os
import json
import re
from dataclasses import dataclass
from typing import List, Dict, Set, Optional
from datetime import datetime


@dataclass
class YARARule:
    """Đại diện một luật YARA"""
    name: str
    meta: Dict[str, str]
    strings: List[Dict[str, str]]
    condition: str


class YARAGenerator:
    """Sinh luật YARA từ nhiều loại features"""
    
    def __init__(self, family_name: str):
        self.family_name = family_name
        self.rule_counter = 0
    
    def generate(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh luật YARA từ tất cả features"""
        rules = []
        
        # 0. Super Rules - gộp strings từ nhiều variants
        if analyses and len(analyses) >= 2:
            super_rules = self._generate_super_rules(feature_sets, analyses)
            rules.extend(super_rules)
        
        # 1. Basic strings (ASCII + Unicode)
        string_rules = self._generate_string_rules(feature_sets, analyses)
        rules.extend(string_rules)
        
        # 2. Hex-encoded strings
        hex_rules = self._generate_hex_string_rules(feature_sets, analyses)
        rules.extend(hex_rules)
        
        # 3. Base64 encoded strings
        b64_rules = self._generate_base64_rules(feature_sets, analyses)
        rules.extend(b64_rules)
        
        # 4. Reversed strings
        reversed_rules = self._generate_reversed_string_rules(feature_sets, analyses)
        rules.extend(reversed_rules)
        
        # 5. Import/EP based rules
        import_rules = self._generate_import_rules(feature_sets)
        rules.extend(import_rules)
        
        # 6. Opcode patterns
        opcode_rules = self._generate_opcode_rules(feature_sets)
        rules.extend(opcode_rules)
        
        return rules
    
    def _generate_super_rules(self, feature_sets: Dict, analyses: List) -> List[YARARule]:
        """Sinh Super Rules - gộp strings xuất hiện ở nhiều variants"""
        rules = []
        
        # Helper to get variant name
        def get_variant_name(a):
            if isinstance(a, dict):
                return a.get("variant", "unknown")
            elif hasattr(a, "variant"):
                return a.variant
            return "unknown"
        
        # Collect all strings with their source variants
        strings = feature_sets.get("strings", [])
        
        # Group strings by the variants they appear in
        # Super rule = strings appear in >= 2 variants
        variant_strings = {}  # {variant_name: set of strings}
        
        for a in analyses:
            variant = get_variant_name(a)
            if variant not in variant_strings:
                variant_strings[variant] = set()
            
            if isinstance(a, dict):
                static = a.get("static", {})
            else:
                static = a.static if hasattr(a, 'static') else {}
            
            if isinstance(static, dict):
                for s in static.get("strings", []):
                    variant_strings[variant].add(s)
        
        # Find strings that appear in multiple variants
        string_to_variants = {}
        for variant, string_set in variant_strings.items():
            for s in string_set:
                if s not in string_to_variants:
                    string_to_variants[s] = []
                string_to_variants[s].append(variant)
        
        # Create super rule with strings appearing in >= 2 variants
        super_strings = []
        for s, variants in string_to_variants.items():
            if len(variants) >= 2 and len(s) >= 6:
                if not self._is_generic_string(s):
                    super_strings.append({
                        "value": s,
                        "modifiers": "ascii wide",
                        "source_info": f"Found in {len(variants)} variants: {', '.join(variants)}"
                    })
        
        if len(super_strings) >= 3:
            rule = YARARule(
                name=f"{self.family_name}_super",
                meta={
                    "description": f"Auto-generated super rule for {self.family_name} - strings common to multiple variants",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "super_rule",
                    "confidence": "high",
                    "family": self.family_name,
                    "variants_covered": str(len(variant_strings)),
                    "super_rule": "true"
                },
                strings=super_strings[:30],
                condition=f"{min(5, len(super_strings))} of them"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_string_rules(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh rules từ basic strings"""
        rules = []
        
        strings = feature_sets.get("strings", [])
        strings_unicode = feature_sets.get("strings_unicode", [])
        
        # Combine and filter high quality strings - use actual frequency from feature
        all_strings = []
        
        # Maximum string length for YARA (YARA has buffer limits)
        MAX_STRING_LENGTH = 500
        
        for s in strings[:100]:
            if s.frequency >= 0.5 and 4 <= len(s.value) <= MAX_STRING_LENGTH:
                if not self._is_generic_string(s.value):
                    all_strings.append((s, "ascii wide"))
        
        for s in strings_unicode[:50]:
            if s.frequency >= 0.5 and 4 <= len(s.value) <= MAX_STRING_LENGTH:
                if not self._is_generic_string(s.value):
                    all_strings.append((s, "wide"))
        
        if len(all_strings) >= 3:
            # Collect sample info for each string
            source_files = set()
            rule_strings = []
            for s, mod in all_strings:
                if hasattr(s, 'samples') and s.samples:
                    source_files.update(s.samples)
                    source_info = f"{len(s.samples)} files: {', '.join(s.samples)}"
                else:
                    source_info = ""
                rule_strings.append({
                    "type": "string",
                    "value": s.value,
                    "modifiers": mod,
                    "source_info": source_info
                })
            
            # Limit to 20 strings per rule and generate condition based on actual count
            strings_to_use = rule_strings[:20]
            actual_string_count = len(strings_to_use)
            
            rule = YARARule(
                name=f"{self.family_name}_strings",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - strings",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "string_based",
                    "confidence": "high" if actual_string_count >= 5 else "medium",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=strings_to_use,
                condition=self._generate_string_condition(actual_string_count)
            )
            
            # Add filesize condition if we have analyses
            if analyses:
                filesize_cond = self._generate_filesize_condition(analyses)
                if filesize_cond:
                    rule.condition = f"({rule.condition}) and {filesize_cond}"
            
            rules.append(rule)
        
        return rules
    
    def _generate_hex_string_rules(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh rules từ hex-encoded strings"""
        rules = []
        
        hex_strings = feature_sets.get("hex_strings", [])
        
        # Limit hex string length and count
        hex_to_use = [s for s in hex_strings[:20] if s.frequency >= 0.7 and len(s.value) <= 100][:10]
        
        if len(hex_to_use) >= 2:
            condition = f"{len(hex_to_use)} of them"
            if analyses:
                filesize_cond = self._generate_filesize_condition(analyses)
                if filesize_cond:
                    condition = f"({condition}) and {filesize_cond}"
            
            rule = YARARule(
                name=f"{self.family_name}_hex_strings",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - hex strings",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "hex_based",
                    "confidence": "medium",
                    "family": self.family_name
                },
                strings=[{"type": "hex", "value": s.value, "modifiers": ""} 
                        for s in hex_to_use],
                condition=condition
            )
            rules.append(rule)
        
        return rules
    
    def _generate_base64_rules(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh rules từ base64 encoded strings"""
        rules = []
        
        b64_strings = feature_sets.get("base64_strings", [])
        
        high_quality_b64 = [s for s in b64_strings[:20] if s.frequency >= 0.6]
        
        if len(high_quality_b64) >= 2:
            condition = "any of them"
            if analyses:
                filesize_cond = self._generate_filesize_condition(analyses)
                if filesize_cond:
                    condition = f"({condition}) and {filesize_cond}"
            
            rule = YARARule(
                name=f"{self.family_name}_base64",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - base64 patterns",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "base64_based",
                    "confidence": "medium",
                    "family": self.family_name
                },
                strings=[{"type": "string", "value": s.value, "modifiers": "base64"} 
                        for s in high_quality_b64[:10]],
                condition=condition
            )
            rules.append(rule)
        
        # Entry point hex rule
        ep_bytes = feature_sets.get("ep_bytes", [])
        if ep_bytes:
            top_ep = ep_bytes[0]
            rule = YARARule(
                name=f"{self.family_name}_ep_bytes",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - entry point",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "entry_point",
                    "confidence": "medium",
                    "family": self.family_name
                },
                strings=[{"type": "hex", "value": top_ep.value, "modifiers": ""}],
                condition="$hex0 at pe.entry_point"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_reversed_string_rules(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh rules từ reversed strings"""
        rules = []
        
        reversed_strings = feature_sets.get("reversed_strings", [])
        
        high_quality_reversed = [s for s in reversed_strings if s.frequency >= 0.7]
        
        if len(high_quality_reversed) >= 2:
            # Get actual strings to use in rule
            strings_to_use = high_quality_reversed[:10]
            # Use 80% threshold based on actual strings in rule
            required = int(len(strings_to_use) * 0.8)
            required = max(1, required)
            condition = f"{required} of them"
            if analyses:
                filesize_cond = self._generate_filesize_condition(analyses)
                if filesize_cond:
                    condition = f"({condition}) and {filesize_cond}"
            
            rule = YARARule(
                name=f"{self.family_name}_reversed",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - reversed strings",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "reversed_string",
                    "confidence": "medium",
                    "family": self.family_name
                },
                strings=[{"type": "string", "value": s.value, "modifiers": "ascii"} 
                        for s in strings_to_use],
                condition=condition
            )
            rules.append(rule)
        
        return rules
    
    def _generate_import_rules(self, feature_sets: Dict, analyses: List = None) -> List[YARARule]:
        """Sinh rules từ imports và imphash"""
        rules = []
        
        imports = feature_sets.get("imports", [])
        
        high_quality_imports = [imp for imp in imports if imp.frequency >= 0.4]
        
        if len(high_quality_imports) >= 2:
            # Get actual strings to use in rule
            strings_to_use = high_quality_imports[:10]
            # Use 80% threshold based on actual strings in rule
            required = int(len(strings_to_use) * 0.8)
            required = max(1, required)
            condition = f"{required} of them"
            if analyses:
                filesize_cond = self._generate_filesize_condition(analyses)
                if filesize_cond:
                    condition = f"({condition}) and {filesize_cond}"
            
            rule = YARARule(
                name=f"{self.family_name}_imports",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - imports",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "import_based",
                    "confidence": "high" if len(strings_to_use) >= 4 else "medium",
                    "family": self.family_name
                },
                strings=[{"type": "string", "value": f"{{{imp.value}}}", "modifiers": "ascii"} 
                        for imp in strings_to_use],
                condition=condition
            )
            rules.append(rule)
        
        # Imphash rules
        imphashes = feature_sets.get("imphash", [])
        
        for imp in imphashes:
            if imp.frequency >= 0.5:
                rule = YARARule(
                    name=f"{self.family_name}_imphash",
                    meta={
                        "description": f"Auto-generated rule for {self.family_name} - imphash",
                        "author": "AutoYaraGen",
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "type": "imphash_based",
                        "confidence": "high",
                        "family": self.family_name
                    },
                    strings=[],
                    condition=f'pe.imphash() == "{imp.value}"'
                )
                rules.append(rule)
                break
        
        return rules
    
    def _generate_opcode_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ opcode patterns"""
        rules = []
        
        opcodes = feature_sets.get("opcodes", [])
        
        high_quality_opcodes = [op for op in opcodes if op.frequency >= 0.4]
        
        if len(high_quality_opcodes) >= 3:
            source_files = set()
            rule_strings = []
            for op in high_quality_opcodes:
                if hasattr(op, 'samples') and op.samples:
                    source_files.update(op.samples)
                    source_info = f"{len(op.samples)} files: {', '.join(op.samples)}"
                else:
                    source_info = ""
                rule_strings.append({
                    "type": "hex",
                    "value": op.value,
                    "modifiers": "",
                    "source_info": source_info
                })
            
            # Get actual strings to use in rule and apply 80% threshold
            strings_to_use = rule_strings[:20]
            required = int(len(strings_to_use) * 0.8)
            required = max(1, required)
            
            rule = YARARule(
                name=f"{self.family_name}_opcodes",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - opcode patterns",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "opcode_based",
                    "confidence": "high" if len(strings_to_use) >= 5 else "medium",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=strings_to_use,
                condition=f"{required} of them"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_string_condition(self, num_strings: int) -> str:
        """Sinh điều kiện YARA - luôn yêu cầu 80% strings match"""
        required = int(num_strings * 0.8)
        # Ensure at least 1 string required
        required = max(1, required)
        return f"{required} of them"
    
    def _generate_filesize_condition(self, analyses: List) -> str:
        """Sinh điều kiện filesize từ kích thước các mẫu"""
        if not analyses:
            return ""
        
        sizes = []
        for a in analyses:
            if isinstance(a, dict):
                static = a.get("static", {})
                if isinstance(static, dict):
                    size = static.get("file_size", 0)
                else:
                    size = getattr(static, "file_size", 0) if hasattr(static, "file_size") else 0
            else:
                size = getattr(a, "file_size", 0) if hasattr(a, "file_size") else 0
            
            if size > 0:
                sizes.append(size)
        
        if not sizes:
            return ""
        
        min_size = min(sizes)
        max_size = max(sizes)
        
        # Convert to KB or MB
        if min_size < 1024 * 1024:
            min_str = f"{min_size // 1024}KB"
        else:
            min_str = f"{min_size // (1024 * 1024)}MB"
        
        if max_size < 1024 * 1024:
            max_str = f"{max_size // 1024}KB"
        else:
            max_str = f"{max_size // (1024 * 1024)}MB"
        
        # Add some tolerance
        min_tolerance = int(min_size * 0.5)
        max_tolerance = int(max_size * 2)
        
        if min_tolerance < 1024 * 1024:
            min_tol_str = f"{max(1, min_tolerance // 1024)}KB"
        else:
            min_tol_str = f"{min_tolerance // (1024 * 1024)}MB"
        
        if max_tolerance < 1024 * 1024:
            max_tol_str = f"{max_tolerance // 1024}KB"
        else:
            max_tol_str = f"{max_tolerance // (1024 * 1024)}MB"
        
        return f"filesize > {min_tol_str} and filesize < {max_tol_str}"
    
    def _is_generic_string(self, s: str) -> bool:
        """Kiểm tra string có quá chung chung không"""
        generic_patterns = [
            r'^[A-Z]:\\',
            r'^\\\\',
            r'^/usr/',
            r'\.dll$',
            r'\.exe$',
            r'^http://',
            r'^https://',
            r'^www\.',
            r'^C:\\Windows',
            r'^C:\\Program',
        ]
        
        s_lower = s.lower()
        for pattern in generic_patterns:
            if re.match(pattern, s_lower):
                return True
        
        return False
    
    def export_yara(self, rules: List[YARARule], output_path: str):
        """Export thành file .yar"""
        content = []
        
        # Import PE module for pe.imphash() and other PE functions
        content.append("import \"pe\"\n")
        
        content.append("/*")
        content.append(f"Auto-generated YARA rules for: {self.family_name}")
        content.append(f"Generated: {datetime.now().isoformat()}")
        content.append(f"Total rules: {len(rules)}")
        content.append("*/\n")
        
        for rule in rules:
            content.append(f"rule {rule.name} {{")
            
            # Meta
            content.append("    meta:")
            for key, value in rule.meta.items():
                content.append(f'        {key} = "{value}"')
            
            # Strings with source info as comments
            if rule.strings:
                content.append("    strings:")
                for i, s in enumerate(rule.strings):
                    if s["type"] == "string":
                        escaped = s["value"].replace('\\', '\\\\').replace('"', '\\"')
                        content.append(f'        $s{i} = "{escaped}" {s["modifiers"]}')
                    elif s["type"] == "hex":
                        content.append(f'        $hex{i} = {{ {s["value"]} }}')
            
            # Condition
            content.append("    condition:")
            for line in rule.condition.split('\n'):
                content.append(f"        {line}")
            
            content.append("}\n")
        
        with open(output_path, "w") as f:
            f.write('\n'.join(content))
        
        print(f"[+] YARA rules exported to: {output_path}")
