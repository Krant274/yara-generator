# main.py
from __future__ import annotations
import os
import json
import argparse
import hashlib
from datetime import datetime
from scr.phase1_collector import MalwareCollector
from scr.phase3_analyzer import StaticAnalyzer
from scr.phase4_feature_systhesis import FeatureSynthesizer
from scr.phase6_yara_generator import YARAGenerator


class AutoYARAPipeline:
    """Pipeline tự động sinh luật YARA từ mẫu malware cùng họ"""
    
    def __init__(self, config: dict):
        self.config = config
        self.family_name = config["family_name"]
        self.work_dir = config.get("work_dir", f"./output_{self.family_name}")
        os.makedirs(self.work_dir, exist_ok=True)
    
    def run(self):
        """Chạy pipeline hoàn chỉnh"""
        print(f"\n{'='*60}")
        print(f"Auto-YARA Generator - {self.family_name}")
        print(f"{'='*60}\n")
        
        # Phase 1: Thu thập mẫu
        samples_dir = self._run_phase1()
        
        # Phase 2: Phân tích tĩnh
        analyses = self._run_phase2(samples_dir)
        
        # Phase 3: Tổng hợp features
        features = self._run_phase3(analyses)
        
        # Phase 4: Sinh YARA
        self._run_phase4(features, analyses)
        
        print(f"\n{'='*60}")
        print("Pipeline completed!")
        print(f"{'='*60}\n")
    
    def _run_phase1(self):
        """Thu thập mẫu từ thư mục đầu vào"""
        print("[*] Phase 1: Sample Collection")
        
        samples_dir = os.path.join(self.work_dir, "samples")
        os.makedirs(samples_dir, exist_ok=True)
        
        collector = MalwareCollector(samples_dir)
        
        input_dir = self.config.get("input_dir")
        if not input_dir:
            print("[!] Error: --input-dir required")
            return samples_dir
        
        if not os.path.exists(input_dir):
            print(f"[!] Input directory not found: {input_dir}")
            return samples_dir
            
        collector.collect_from_directory(input_dir, self.family_name)
        
        collector.save_manifest(os.path.join(samples_dir, "manifest.json"))
        print(f"    Collected: {len(collector.samples)} samples")
        
        return samples_dir
    
    def _run_phase2(self, samples_dir: str):
        """Phân tích tĩnh tất cả files trong mỗi mẫu"""
        print("[*] Phase 2: Static Analysis")
        
        analyzer = StaticAnalyzer()
        
        # Find samples directory
        samples_subdir = os.path.join(samples_dir, "samples")
        if not os.path.exists(samples_subdir):
            samples_subdir = samples_dir
        
        # Get all variant directories
        variants = [d for d in os.listdir(samples_subdir)
                   if os.path.isdir(os.path.join(samples_subdir, d))]
        
        analyses = []
        for variant in variants:
            variant_dir = os.path.join(samples_subdir, variant)
            files = [f for f in os.listdir(variant_dir)
                    if os.path.isfile(os.path.join(variant_dir, f))]
            
            if not files:
                continue
            
            print(f"    Analyzing: {variant} ({len(files)} files)")
            
            # Aggregate features from all files
            combined = analyzer.analyze_directory(variant_dir)
            
            # Calculate hash from first file
            first_file = os.path.join(variant_dir, files[0])
            md5, sha256 = self._calculate_hash(first_file)
            
            analyses.append({
                "file_path": variant_dir,
                "variant": variant,
                "md5": md5,
                "sha256": sha256,
                "static": combined
            })
        
        # Save analysis results
        results = []
        for a in analyses:
            static = a["static"]
            results.append({
                "file_path": a["file_path"],
                "md5": a["md5"],
                "sha256": a["sha256"],
                "static": {
                    "strings": list(static.strings),
                    "strings_unicode": list(static.strings_unicode),
                    "hex_strings": list(static.hex_strings),
                    "base64_strings": list(static.base64_strings),
                    "reversed_strings": list(static.reversed_strings),
                    "imports": list(static.imports),
                    "exports": list(static.exports),
                    "imphash": static.imphash,
                    "ep_bytes": static.ep_bytes,
                    "entropy": static.entropy,
                    "file_size": static.file_size,
                    "headers": static.headers,
                    "version_info": static.version_info,
                    "pe_sections": static.pe_sections,
                    "resources": static.resources,
                    "section_entropies": static.section_entropies,
                }
            })
        
        with open(os.path.join(self.work_dir, "analysis_results.json"), "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"    Analyzed: {len(analyses)} samples")
        return analyses
    
    def _run_phase3(self, analyses):
        """Tổng hợp features chung"""
        print("[*] Phase 3: Feature Synthesis")
        
        min_freq = self.config.get("min_frequency", 0.7)
        dbs_dir = self.config.get("dbs_dir", "./dbs")
        synthesizer = FeatureSynthesizer(min_frequency=min_freq, dbs_dir=dbs_dir, auto_download=True)
        features = synthesizer.synthesize(analyses)
        
        # Save features
        output = {}
        for ftype, flist in features.items():
            output[ftype] = [
                {"value": f.value, "frequency": f.frequency, "count": f.samples_count, "score": f.score}
                for f in flist[:50]
            ]
        
        with open(os.path.join(self.work_dir, "features.json"), "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"    Strings: {len(features.get('strings', []))}")
        print(f"    Imports: {len(features.get('imports', []))}")
        
        return features
    
    def _run_phase4(self, features, analyses):
        """Sinh luật YARA"""
        print("[*] Phase 4: YARA Generation")
        
        generator = YARAGenerator(self.family_name)
        rules = generator.generate(features, analyses)
        
        # Export YARA
        yara_path = os.path.join(self.work_dir, f"{self.family_name}.yar")
        generator.export_yara(rules, yara_path)
        
        # Save metadata
        metadata = {
            "family": self.family_name,
            "generated_at": datetime.now().isoformat(),
            "total_samples": len(analyses),
            "samples": [a["sha256"] for a in analyses]
        }
        with open(os.path.join(self.work_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"    Generated: {len(rules)} rules")
        print(f"    Saved to: {yara_path}")
    
    def _calculate_hash(self, file_path: str):
        """Tính MD5 và SHA256"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        
        return md5.hexdigest(), sha256.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Auto-YARA Generator")
    parser.add_argument("--family", required=True, help="Malware family name")
    parser.add_argument("--input-dir", required=True, help="Input directory containing malware samples (each subdirectory = 1 variant)")
    parser.add_argument("--min-freq", type=float, default=0.7, help="Min feature frequency (0.3-1.0)")
    parser.add_argument("--output", default="./output", help="Output directory")
    parser.add_argument("--dbs-dir", default="./dbs", help="Directory containing yarGen whitelist databases")
    
    args = parser.parse_args()
    
    if args.min_freq < 0.3 or args.min_freq > 1.0:
        print("[!] min-freq must be between 0.3 and 1.0")
        return
    
    config = {
        "family_name": args.family,
        "input_dir": args.input_dir,
        "min_frequency": args.min_freq,
        "work_dir": args.output,
        "dbs_dir": args.dbs_dir
    }
    
    pipeline = AutoYARAPipeline(config)
    pipeline.run()


if __name__ == "__main__":
    main()
