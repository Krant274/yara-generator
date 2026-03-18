# src/phase3_analyzer.py
import os
import json
import subprocess
import hashlib
import re
import string
import base64
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


@dataclass
class StaticFeatures:
    """Đặc trưng tĩnh"""
    # Basic strings
    strings: Set[str] = field(default_factory=set)
    strings_unicode: Set[str] = field(default_factory=set)
    
    # Enhanced string analysis
    hex_strings: Set[str] = field(default_factory=set)
    base64_strings: Set[str] = field(default_factory=set)
    reversed_strings: Set[str] = field(default_factory=set)
    
    # Opcode analysis
    opcodes: Set[str] = field(default_factory=set)
    opcode_sequences: List[str] = field(default_factory=list)
    
    # PE metadata
    imports: Set[str] = field(default_factory=set)
    exports: Set[str] = field(default_factory=set)
    pe_sections: List[Dict] = field(default_factory=list)
    imphash: Optional[str] = None
    ep_bytes: Optional[str] = None
    section_entropies: Dict[str, float] = field(default_factory=dict)
    resources: List[Dict] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    version_info: Dict = field(default_factory=dict)
    
    # File characteristics
    file_size: int = 0
    entropy: float = 0.0


class StaticAnalyzer:
    """Phân tích tĩnh nâng cao"""
    
    def __init__(self):
        self.min_string_length = 6
    
    def analyze(self, file_path: str) -> StaticFeatures:
        """Phân tích tĩnh toàn diện"""
        features = StaticFeatures()
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        features.file_size = len(data)
        
        # 1. Basic strings
        features.strings = self._extract_strings(data, "ascii")
        features.strings_unicode = self._extract_strings(data, "utf-16le")
        
        # 2. Enhanced strings
        features.hex_strings = self._extract_hex_strings(data)
        features.base64_strings = self._extract_base64_strings(data)
        features.reversed_strings = self._extract_reversed_strings(data)
        
        # 3. Calculate entropy
        features.entropy = self._calculate_entropy(data)
        
        # 4. Opcode analysis (simple pattern-based)
        if self._is_pe_file(data):
            features = self._extract_opcodes(data, features)
        
        # 5. PE analysis
        if self._is_pe_file(data):
            features = self._analyze_pe(data, features)
        
        # 5. Section entropies
        features.section_entropies = self._calculate_section_entropies(data)
        
        return features
    
    def _extract_hex_strings(self, data: bytes) -> Set[str]:
        """Trích xuất hex-encoded strings (ví dụ: 4D5A0000)"""
        hex_strings = set()
        
        # Tìm sequences of hex bytes có thể là strings
        # Pattern: 4-50 ký tự hex liên tiếp
        hex_pattern = re.compile(rb'(?:[0-9A-Fa-f]{2}){4,50}')
        
        for match in hex_pattern.findall(data):
            try:
                decoded = match.decode('ascii')
                # Chỉ lấy nếu decode được thành printable chars
                decoded_bytes = bytes.fromhex(decoded)
                if all(0x20 <= b < 0x7F or b in [0x0A, 0x0D, 0x09] for b in decoded_bytes):
                    if len(decoded_bytes) >= 4:
                        hex_strings.add(decoded)
            except:
                pass
        
        return hex_strings
    
    def _extract_base64_strings(self, data: bytes) -> Set[str]:
        """Trích xuất base64-encoded strings"""
        b64_strings = set()
        
        # Tìm pattern base64 thường gặp
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{8,}={0,2}')
        
        for match in b64_pattern.findall(data):
            try:
                decoded = base64.b64decode(match)
                # Chỉ lấy nếu decode ra readable content
                if all(0x20 <= b < 0x7F or b in [0x0A, 0x0D, 0x09] for b in decoded[:50]):
                    b64_strings.add(match.decode('ascii'))
            except:
                pass
        
        return b64_strings
    
    def _extract_reversed_strings(self, data: bytes) -> Set[str]:
        """Trích xuất reversed strings (thường dùng trong malware)"""
        reversed_strings = set()
        
        # Tìm strings có thể là reversed
        ascii_strings = re.findall(rb'[\x20-\x7E]{6,}', data)
        
        for s in ascii_strings:
            try:
                normal = s.decode('ascii')
                reversed_str = normal[::-1]
                
                # Kiểm tra reversed có ý nghĩa không
                # (không phải palindrome, có nghĩa khi đảo ngược)
                if normal != reversed_str and len(normal) >= 6:
                    # Check if reversed version is also a valid string
                    if all(c in string.printable for c in reversed_str[:10]):
                        reversed_strings.add(reversed_str)
            except:
                pass
        
        return reversed_strings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Tính Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
    
    def _analyze_pe(self, data: bytes, features: StaticFeatures) -> StaticFeatures:
        """Phân tích chi tiết PE file"""
        try:
            import pefile
            
            pe = pefile.PE(data=data)
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    features.imports.add(dll_name.lower())
                    for imp in entry.imports:
                        if imp.name:
                            features.imports.add(imp.name.decode('utf-8', errors='ignore').lower())
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        features.exports.add(exp.name.decode('utf-8', errors='ignore').lower())
            
            # Sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                features.pe_sections.append({
                    "name": section_name,
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 2),
                    "characteristics": hex(section.Characteristics)
                })
                features.section_entropies[section_name] = round(section.get_entropy(), 2)
            
            # Import hash
            features.imphash = pe.get_imphash()
            
            # Entry point bytes
            if pe.OPTIONAL_HEADER.AddressOfEntryPoint:
                ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                ep_bytes = data[ep_offset:ep_offset + 32]
                features.ep_bytes = ' '.join([f'{b:02x}' for b in ep_bytes])
            
            # Resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    features.resources.append({
                                        "type": resource_type.id,
                                        "id": resource_id.id,
                                        "lang": resource_lang.id,
                                        "size": resource_lang.data.struct.Size
                                    })
            
            # Version info
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                vs = pe.VS_FIXEDFILEINFO[0]
                features.version_info = {
                    "signature": vs.Signature,
                    "file_version_ms": vs.FileVersionMS,
                    "file_version_ls": vs.FileVersionLS,
                    "product_version_ms": vs.ProductVersionMS,
                    "product_version_ls": vs.ProductVersionLS,
                }
            
            # Headers
            features.headers = {
                "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "image_base": pe.OPTIONAL_HEADER.ImageBase,
                "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
                "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
            }
            
        except ImportError:
            print("        [!] pip install pefile")
        except Exception:
            pass
        
        return features
    
    def _calculate_section_entropies(self, data: bytes) -> Dict[str, float]:
        """Tính entropy từng vùng trong file"""
        entropies = {}
        chunk_size = 512
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) < 100:
                continue
            
            byte_counts = [0] * 256
            for byte in chunk:
                byte_counts[byte] += 1
            
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    prob = count / len(chunk)
                    entropy -= prob * math.log2(prob)
            
            entropies[f"offset_0x{i:08x}"] = round(entropy, 2)
        
        return entropies
    
    def _extract_strings(self, data: bytes, encoding: str) -> Set[str]:
        """Trích xuất strings có ý nghĩa"""
        strings = set()
        
        if encoding == "ascii":
            pattern = re.compile(rb'[\x20-\x7E]{%d,}' % self.min_string_length)
            for match in pattern.findall(data):
                try:
                    s = match.decode('ascii')
                    if self._is_meaningful_string(s):
                        strings.add(s)
                except:
                    pass
        else:
            pattern = re.compile(rb'(?:[\x20-\x7E]\x00){%d,}' % self.min_string_length)
            for match in pattern.findall(data):
                try:
                    s = match.decode('utf-16le')
                    if self._is_meaningful_string(s):
                        strings.add(s)
                except:
                    pass
        
        return strings
    
    def _is_meaningful_string(self, s: str) -> bool:
        """Kiểm tra string có ý nghĩa"""
        if len(s) < self.min_string_length:
            return False
        if s.isdigit():
            return False
        
        allowed = set(s) - set(string.printable)
        if len(allowed) > len(s) * 0.5:
            return False
        
        common_patterns = [r'^[A-Z]:\\', r'^/usr/', r'\.dll$', r'\.exe$']
        for pattern in common_patterns:
            if re.match(pattern, s, re.IGNORECASE):
                return False
        
        return True
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Kiểm tra có phải PE file"""
        return data[:2] == b'MZ'
    
    def analyze_directory(self, dir_path: str) -> StaticFeatures:
        """Phân tích tất cả files trong directory và gộp features"""
        combined = StaticFeatures()
        
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            
            if not os.path.isfile(file_path):
                continue
            
            try:
                result = self.analyze(file_path)
                
                # Merge basic strings
                combined.strings.update(result.strings)
                combined.strings_unicode.update(result.strings_unicode)
                
                # Merge enhanced strings
                combined.hex_strings.update(result.hex_strings)
                combined.base64_strings.update(result.base64_strings)
                combined.reversed_strings.update(result.reversed_strings)
                
                # Merge opcodes
                combined.opcodes.update(result.opcodes)
                combined.opcode_sequences.extend(result.opcode_sequences)
                
                # Merge PE features
                combined.imports.update(result.imports)
                combined.exports.update(result.exports)
                
                # Take first non-None values
                if not combined.imphash and result.imphash:
                    combined.imphash = result.imphash
                if not combined.ep_bytes and result.ep_bytes:
                    combined.ep_bytes = result.ep_bytes
                if not combined.headers and result.headers:
                    combined.headers = result.headers
                if not combined.version_info and result.version_info:
                    combined.version_info = result.version_info
                
                # Merge sections and resources
                combined.pe_sections.extend(result.pe_sections)
                combined.resources.extend(result.resources)
                
                # Update file stats (take max)
                if result.file_size > combined.file_size:
                    combined.file_size = result.file_size
                if result.entropy > combined.entropy:
                    combined.entropy = result.entropy
                    
            except Exception as e:
                print(f"        Warning: Error analyzing {filename}: {e}")
        
        return combined
    
    def _extract_strings(self, data: bytes, encoding: str) -> Set[str]:
        """Trích xuất strings có ý nghĩa"""
        strings = set()
        
        if encoding == "ascii":
            pattern = re.compile(rb'[\x20-\x7E]{%d,}' % self.min_string_length)
            for match in pattern.findall(data):
                try:
                    s = match.decode('ascii')
                    if self._is_meaningful_string(s):
                        strings.add(s)
                except:
                    pass
        else:  # utf-16le
            pattern = re.compile(rb'(?:[\x20-\x7E]\x00){%d,}' % self.min_string_length)
            for match in pattern.findall(data):
                try:
                    s = match.decode('utf-16le')
                    if self._is_meaningful_string(s):
                        strings.add(s)
                except:
                    pass
        
        return strings
    
    def _is_meaningful_string(self, s: str) -> bool:
        """Kiểm tra string có ý nghĩa hay không"""
        # Loại bỏ strings quá ngắn
        if len(s) < self.min_string_length:
            return False
        
        # Loại bỏ strings chỉ có số
        if s.isdigit():
            return False
        
        # Loại bỏ strings toàn ký tự đặc biệt
        allowed = set(s) - set(string.printable)
        if len(allowed) > len(s) * 0.5:
            return False
        
        # Loại bỏ patterns quá phổ biến
        common_patterns = [
            r'^[A-Z]:\\',  # Windows paths
            r'^/usr/',
            r'\.dll$',
            r'\.exe$',
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, s, re.IGNORECASE):
                return False
        
        return True
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Kiểm tra có phải PE file"""
        return data[:2] == b'MZ'
    
    def _extract_opcodes(self, data: bytes, features: StaticFeatures) -> StaticFeatures:
        """Trích xuất opcode patterns sử dụng Capstone disassembly"""
        
        try:
            import pefile
            import capstone
            
            pe = pefile.PE(data=data)
            
            if not pe.OPTIONAL_HEADER.AddressOfEntryPoint:
                return features
                
            ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            code_region = data[ep_offset:ep_offset + 1024]
            
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            md.detail = False
            
            opcode_ngrams = []
            for insn in md.disasm(code_region, ep_offset):
                hex_bytes = insn.bytes.hex()
                features.opcodes.add(hex_bytes)
                
                opcode_ngrams.append(hex_bytes[:2])
                
                if len(insn.bytes) >= 2:
                    opcode_ngrams.append(hex_bytes[:4])
                
                if len(insn.bytes) >= 3:
                    opcode_ngrams.append(hex_bytes[:6])
            
            features.opcode_sequences = opcode_ngrams[:100]
                    
        except ImportError:
            pass
        except Exception:
            pass
        
        return features
    


