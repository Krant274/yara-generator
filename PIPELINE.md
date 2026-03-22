# Pipeline Hoạt Động - Auto-YARA Generator

## Tổ Quan

Chương trình tự động sinh luật YARA từ mẫu malware cùng họ (family).

```
Input Files → Phase 1 → Phase 2 → Phase 3 → Phase 4 → YARA Rules
            Collector  Analyzer  Synthesizer Generator
```

---

## Cấu Trúc Input

**Yêu cầu:** Mỗi subdirectory = 1 variant của malware

```
malware_samples/
├── Variant_A/
│   ├── malware1.exe
│   └── config.dat
├── Variant_B/
│   └── malware2.exe
└── Variant_C/
    └── payload.dll
```

---

## Phase 1: Thu Thập Mẫu (Collection)

**File:** `scr/phase1_collector.py`

### Mục tiêu
Copy mẫu malware từ thư mục đầu vào vào thư mục làm việc.

### Cách hoạt động

```
1. Đọc thư mục đầu vào
   └── Mỗi subdirectory = 1 variant (bắt buộc)

2. Duyệt tất cả files trong từng variant
   └── Thu thập TẤT CẢ các file 

3. Kiểm tra file hợp lệ
   └── Kích thước: 512 bytes - 100MB

4. Copy file vào output/samples/<variant>/
   └── Tính MD5, SHA256
   └── Phát hiện loại file (PE32/PE64/ELF)

5. Xuất manifest.json
```

### Output
- Thư mục `samples/`
- File `manifest.json` (danh sách mẫu)

---

## Phase 2: Phân Tích Tĩnh (Analysis)

**File:** `scr/phase3_analyzer.py`

### Mục tiêu
Trích xuất đặc trưng (features) từ mỗi file.

### Cách hoạt động

```
Với mỗi file:
├── 1. Đọc toàn bộ file vào memory
├── 2. Trích xuất Strings
│   ├── ASCII strings (độ dài ≥ 6)
│   ├── Unicode strings (UTF-16LE)
│   ├── Hex strings (encoded)
│   ├── Base64 strings (encoded)
│   └── Reversed strings (đảo ngược - tránh detection)
├── 3. Tính Entropy
│   ├── Shannon entropy toàn bộ file
│   └── Entropy từng vùng 512 bytes
├── 4. Nếu là PE file → Phân tích PE
│   ├── Imports (DLL + API)
│   ├── Exports
│   ├── Sections (.text, .data, .rsrc...)
│   ├── imphash
│   ├── Entry Point bytes (32 bytes đầu)
│   ├── Resources
│   ├── Version Info
│   └── Headers
└── 5. Trích xuất Opcodes (nếu là PE)
    ├── Disassemble từ Entry Point (Capstone)
    └── Opcode n-grams
```

### Output
File `analysis_results.json` chứa tất cả features

---

## Phase 3: Tổng Hợp Features (Synthesis)

**File:** `scr/phase4_feature_systhesis.py`

### Mục tiêu
Tìm features chung và lọc whitelist.

### Cách hoạt động

```
1. Kiểm tra whitelist databases
   └── Nếu chưa có → Tự động tải từ GitHub

2. Load whitelist vào memory
   ├── good-strings-*.db (~12M strings)
   ├── good-opcodes-*.db (~34M opcodes)
   ├── good-imphashes-*.db (~19K imphashes)
   └── good-exports-*.db (~404K exports)

3. String Scoring (giống yarGen ~60 patterns)
   ├── Patterns tăng điểm:
   │   ├── IP address (+5)
   │   ├── Malware names (+10)
   │   ├── Process injection APIs (+7)
   │   ├── System keywords (+5)
   │   └── File extensions (+4)
   └── Patterns giảm điểm:
       ├── Generic DOS strings (-10)
       ├── Certificates (-4)
       └── Packer strings (-4)

4. Với mỗi loại feature:
   ├── Đếm số lần xuất hiện trong các mẫu
   ├── Tính frequency = count / total_samples
   ├── Lọc theo min_frequency (mặc định 0.7)
   └── Lọc bỏ features trong whitelist
```

### String Scoring Chi Tiết

| Pattern | Điểm | Ví dụ |
|---------|------|--------|
| IP Address | +5 | 192.168.1.1 |
| Malware name | +10 | ransomware, wannacry, emotet |
| Process injection | +7 | VirtualAlloc, WriteProcessMemory |
| System keywords | +5 | cmd.exe, system32, password |
| Protocol keywords | +5 | ftp, http, smtp |
| File extensions | +4 | .exe, .dll, .scr |
| Drive letter | +2 | C:\ |
| Generic DOS | -10 | "This program cannot be run in DOS mode" |
| Certificates | -4 | thawte, trustcenter |

### Output
File `features.json` chứa features đã lọc và chấm điểm

---

## Phase 4: Sinh Luật YARA (Generation)

**File:** `scr/phase6_yara_generator.py`

### Mục tiêu
Tạo các luật YARA từ features.

### Cách hoạt động

```
1. Super Rules (ưu tiên cao nhất)
   └── Gộp strings từ ≥ 2 variants
   └── Tạo 1 rule chung cho cả family

2. String Rules
   ├── ASCII + Unicode strings (freq ≥ 0.5, len ≤ 500)
   └── Condition: "80% of them" + filesize

3. Hex String Rules
   ├── Hex-encoded strings (freq ≥ 0.7, len ≤ 100)
   └── Condition: "80% of them" + filesize

4. Base64 Rules
   ├── Base64 patterns (freq ≥ 0.6)
   └── Condition: "any of them" + filesize

5. Reversed String Rules
   ├── Reversed strings (freq ≥ 0.7)
   └── Condition: "80% of them" + filesize

6. Import Rules
   ├── Characteristic imports (freq ≥ 0.4)
   └── Condition: "80% of them"

7. Opcode Rules
   ├── Opcode patterns (freq ≥ 0.4)
   └── Condition: "80% of them"

8. Imphash Rules
   └── pe.imphash() == "hash_value"

9. Entry Point Rules
   └── Hex pattern tại pe.entry_point
```

### Condition Trong YARA

**Condition** xác định khi nào rule match với file:

| Loại | Ví dụ | Mô tả |
|------|-------|--------|
| String match | `16 of them` | 80% strings phải match |
| PE Header | `uint16(0) == 0x5A4D` | 2 bytes đầu = "MZ" |
| Filesize | `filesize > 1MB and filesize < 10MB` | Kích thước trong khoảng |
| Entry Point | `$hex0 at pe.entry_point` | Hex pattern tại EP |
| Imphash | `pe.imphash() == "..."` | Import hash match |

### Filesize Condition
- Tự động tính min/max size từ các mẫu
- Thêm tolerance (0.5x - 2x)
- Ví dụ: `filesize > 1MB and filesize < 10MB`

### Output
- File `{family}.yar` - Luật YARA
- File `metadata.json` - Thông tin tổng hợp

---

## Các Rules Được Sinh Ra

```
rule FamilyName_strings {
    strings: $s0-$s19 (20 strings)
    condition: (16 of them) and filesize > X and filesize < Y
}

rule FamilyName_hex_strings { ... }

rule FamilyName_base64 { ... }

rule FamilyName_reversed { ... }

rule FamilyName_imports { ... }

rule FamilyName_opcodes { ... }

rule FamilyName_imphash { ... }

rule FamilyName_ep_bytes { ... }

rule FamilyName_super { ... }  # Strings chung từ ≥ 2 variants
```

---

## Cách Chạy

```bash
python main.py \
    --family "Ransomware.WannaCry" \
    --input-dir /path/to/malware/samples \
    --min-freq 0.7 \
    --output ./output \
    --dbs-dir ./dbs
```

| Tham số | Mô tả | Mặc định |
|---------|-------|-----------|
| `--family` | Tên malware family | Required |
| `--input-dir` | Thư mục đầu vào (mỗi subdir = 1 variant) | Required |
| `--min-freq` | Tần suất tối thiểu (0.3-1.0) | 0.7 |
| `--output` | Thư mục output | ./output |
| `--dbs-dir` | Thư mục whitelist | ./dbs |

---

## Luồng Dữ Liệu Hoàn Chỉnh

```
┌─────────────────────────────────────────────────────────┐
│ Input: /path/to/malware/samples                         │
│   (mỗi subdirectory = 1 variant)                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 1: MalwareCollector                              │
│ • Copy files to output/samples/                        │
│ • Calculate hashes                                     │
│ • Detect file type                                     │
│ Output: samples/ + manifest.json                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 2: StaticAnalyzer                                │
│ • Extract strings, hex, base64, reversed              │
│ • Calculate entropy                                    │
│ • Analyze PE (imports, exports, sections...)          │
│ • Extract opcodes (Capstone)                          │
│ Output: analysis_results.json                          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 3: FeatureSynthesizer                            │
│ • Load whitelist (auto-download if missing)           │
│ • String scoring (60+ patterns like yarGen)           │
│ • Count frequency per feature                         │
│ • Filter by min_frequency + whitelist                │
│ Output: features.json                                  │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 4: YARAGenerator                                 │
│ • Super Rules (multi-variant strings)                 │
│ • String/hex/base64/reversed rules                    │
│ • Import/imphash/opcode rules                         │
│ • EP bytes rule                                       │
│ • 80% condition threshold                             │
│ • Add filesize condition                              │
│ Output: {family}.yar + metadata.json                  │
└─────────────────────────────────────────────────────────┘
```

## Yêu Cầu Hệ Thống

- Python 3.8+
- pefile
- capstone
- lxml (tùy chọn cho PEStudio scoring)
- requests (cho auto-download)

```bash
pip install -r requirements.txt
```
