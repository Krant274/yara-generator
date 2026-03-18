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
        
        # 1. Basic strings (ASCII + Unicode)
        string_rules = self._generate_string_rules(feature_sets)
        rules.extend(string_rules)
        
        # 2. Hex-encoded strings
        hex_rules = self._generate_hex_string_rules(feature_sets)
        rules.extend(hex_rules)
        
        # 3. Base64 encoded strings
        b64_rules = self._generate_base64_rules(feature_sets)
        rules.extend(b64_rules)
        
        # 4. Reversed strings
        reversed_rules = self._generate_reversed_string_rules(feature_sets)
        rules.extend(reversed_rules)
        
        # 5. Import/EP based rules
        import_rules = self._generate_import_rules(feature_sets)
        rules.extend(import_rules)
        
        # 6. Opcode patterns
        opcode_rules = self._generate_opcode_rules(feature_sets)
        rules.extend(opcode_rules)
        
        # 7. Composite rules (entropy, PE headers)
        if analyses:
            composite_rules = self._generate_composite_rules(feature_sets, analyses)
            rules.extend(composite_rules)
        
        return rules
    
    def _generate_string_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ basic strings"""
        rules = []
        
        strings = feature_sets.get("strings", [])
        strings_unicode = feature_sets.get("strings_unicode", [])
        
        # Combine and filter high quality strings - use actual frequency from feature
        all_strings = []
        
        for s in strings[:100]:
            if s.frequency >= 0.5 and len(s.value) >= 4:  # Use feature's actual frequency
                if not self._is_generic_string(s.value):
                    all_strings.append((s, "ascii wide"))
        
        for s in strings_unicode[:50]:
            if s.frequency >= 0.5 and len(s.value) >= 4:
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
            
            rule = YARARule(
                name=f"{self.family_name}_strings",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - strings",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "string_based",
                    "confidence": "high" if len(all_strings) >= 5 else "medium",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=rule_strings[:20],
                condition=self._generate_string_condition(len(all_strings))
            )
            rules.append(rule)
        
        return rules
    
    def _generate_hex_string_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ hex-encoded strings"""
        rules = []
        
        hex_strings = feature_sets.get("hex_strings", [])
        
        high_quality_hex = [s for s in hex_strings[:20] if s.frequency >= 0.7]
        
        if len(high_quality_hex) >= 2:
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
                        for s in high_quality_hex[:10]],
                condition=f"{len(high_quality_hex)} of them"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_base64_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ base64 encoded strings"""
        rules = []
        
        b64_strings = feature_sets.get("base64_strings", [])
        
        high_quality_b64 = [s for s in b64_strings[:20] if s.frequency >= 0.6]
        
        if len(high_quality_b64) >= 2:
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
                condition=f"any of them"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_reversed_string_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ reversed strings"""
        rules = []
        
        reversed_strings = feature_sets.get("reversed_strings", [])
        
        high_quality_reversed = []
        for s in reversed_strings[:50]:
            if s.frequency >= 0.7 and len(s.value) >= 6:
                # Kiểm tra reversed có ý nghĩa
                if not self._is_generic_string(s.value):
                    high_quality_reversed.append(s)
        
        if len(high_quality_reversed) >= 3:
            # Add source info for each string
            source_files = set()
            rule_strings = []
            for s in high_quality_reversed:
                if hasattr(s, 'samples') and s.samples:
                    source_files.update(s.samples)
                    source_info = f"{len(s.samples)} files: {', '.join(s.samples)}"
                else:
                    source_info = ""
                rule_strings.append({
                    "type": "string",
                    "value": s.value,
                    "modifiers": "ascii wide",
                    "source_info": source_info
                })
            
            rule = YARARule(
                name=f"{self.family_name}_reversed",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - reversed strings",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "reversed_string_based",
                    "confidence": "high" if len(high_quality_reversed) >= 5 else "medium",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=rule_strings[:15],
                condition=self._generate_string_condition(len(high_quality_reversed))
            )
            rules.append(rule)
        
        return rules
    
    def _generate_import_rules(self, feature_sets: Dict) -> List[YARARule]:
        """Sinh rules từ imports và entry point"""
        rules = []
        
        imports = feature_sets.get("imports", [])
        
        # Import-based rule - use actual frequency
        characteristic_imports = [imp for imp in imports if imp.frequency >= 0.4]
        
        if len(characteristic_imports) >= 3:
            # Add source info for each import
            source_files = set()
            rule_strings = []
            for imp in characteristic_imports:
                if hasattr(imp, 'samples') and imp.samples:
                    source_files.update(imp.samples)
                    source_info = f"{len(imp.samples)} files: {', '.join(imp.samples)}"
                else:
                    source_info = ""
                rule_strings.append({
                    "type": "string",
                    "value": imp.value,
                    "modifiers": "ascii",
                    "source_info": source_info
                })
            
            rule = YARARule(
                name=f"{self.family_name}_imports",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - imports",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "import_based",
                    "confidence": "high",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=rule_strings[:15],
                condition="any of them"
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
                condition="$hex0 at entrypoint"
            )
            rules.append(rule)
        
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
            
            rule = YARARule(
                name=f"{self.family_name}_opcodes",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - opcode patterns",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "opcode_based",
                    "confidence": "high" if len(high_quality_opcodes) >= 5 else "medium",
                    "family": self.family_name,
                    "source_files": ", ".join(sorted(source_files)) if source_files else "unknown"
                },
                strings=rule_strings[:20],
                condition="any of them"
            )
            rules.append(rule)
        
        return rules
    
    def _generate_composite_rules(self, feature_sets: Dict, analyses: List) -> List[YARARule]:
        """Sinh composite rules (entropy, PE headers)"""
        rules = []
        
        # Helper to get static from either dict or object
        def get_static(a):
            if isinstance(a, dict):
                return a.get("static", {})
            elif hasattr(a, "static"):
                return a.static
            return {}
        
        # Check entropy patterns
        entropies = []
        for a in analyses:
            static = get_static(a)
            if isinstance(static, dict):
                entropies.append(static.get("entropy", 0))
            else:
                entropies.append(getattr(static, "entropy", 0))
        
        if entropies:
            avg_entropy = sum(entropies) / len(entropies)
            
            # High entropy = packed/encrypted
            if avg_entropy > 6.5:
                rule = YARARule(
                    name=f"{self.family_name}_high_entropy",
                    meta={
                        "description": f"Auto-generated rule for {self.family_name} - high entropy",
                        "author": "AutoYaraGen",
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "type": "entropy_based",
                        "confidence": "medium",
                        "family": self.family_name,
                        "avg_entropy": str(round(avg_entropy, 2))
                    },
                    strings=[],
                    condition="filesize > 10KB and filesize < 10MB"
                )
                rules.append(rule)
        
        # PE header check
        pe_count = 0
        for a in analyses:
            static = get_static(a)
            if isinstance(static, dict):
                headers = static.get("headers", {})
                if headers and headers.get("machine"):
                    pe_count += 1
            elif hasattr(static, "headers") and static.headers:
                if static.headers.get("machine"):
                    pe_count += 1
        
        if pe_count >= len(analyses) * 0.5:
            rule = YARARule(
                name=f"{self.family_name}_pe_header",
                meta={
                    "description": f"Auto-generated rule for {self.family_name} - PE header",
                    "author": "AutoYaraGen",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "type": "pe_header",
                    "confidence": "high",
                    "family": self.family_name,
                    "coverage": f"{pe_count}/{len(analyses)} samples"
                },
                strings=[],
                condition="uint16(0) == 0x5A4D"  # MZ header
            )
            rules.append(rule)
        
        return rules
    
    def _generate_string_condition(self, num_strings: int) -> str:
        """Sinh điều kiện YARA"""
        if num_strings >= 8:
            return f"{num_strings - 2} of them"
        elif num_strings >= 5:
            return f"{num_strings - 1} of them"
        else:
            return f"{num_strings} of them"
    
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
                        # Get source info if available
                        source_info = s.get("source_info", "")
                        if source_info:
                            comment = f" // Found in: {source_info}"
                        else:
                            comment = ""
                        content.append(f'        $s{i} = "{escaped}" {s["modifiers"]}{comment}')
                    elif s["type"] == "hex":
                        source_info = s.get("source_info", "")
                        if source_info:
                            comment = f" // Found in: {source_info}"
                        else:
                            comment = ""
                        content.append(f'        $hex{i} = {{ {s["value"]} }}{comment}')
            
            # Condition
            content.append("    condition:")
            for line in rule.condition.split('\n'):
                content.append(f"        {line}")
            
            content.append("}\n")
        
        with open(output_path, "w") as f:
            f.write('\n'.join(content))
        
        print(f"[+] YARA rules exported to: {output_path}")
