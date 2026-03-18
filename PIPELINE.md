# Pipeline Hoạt Động - Auto-YARA Generator

## Tổng Quan

Pipeline tự động sinh luật YARA từ mẫu malware cùng họ. Gồm 4 giai đoạn chính:

```
Input Files → Phase 1 → Phase 2 → Phase 3 → Phase 4 → YARA Rules
                      (Analyzer) (Synthesizer) (Generator)
```

---

## Phase 1: Thu Thập Mẫu (Collection)

**File:** `scr/phase1_collector.py`

**Mục tiêu:** Copy mẫu malware từ thư mục đầu vào vào thư mục làm việc.

**Cách hoạt động:**

```
1. Đọc thư mục đầu vào
   └── Mỗi subdirectory = 1 variant (biến thể)

2. Duyệt tất cả files trong từng variant
   └── Bỏ qua thư mục con

3. Kiểm tra file hợp lệ
   └── Kích thước: 512 bytes - 100MB
   └── Chấp nhận TẤT CẢ các đuôi file

4. Copy file vào output/samples/<variant>/
   └── Tính MD5, SHA256
   └── Phát hiện loại file (PE32/PE64/ELF)

5. Xuất manifest.json
   └── Danh sách các mẫu đã thu thập
```

**Input:** Thư mục chứa malware theo cấu trúc:
```
malware_samples/
├── Variant_A/
│   ├── file1.exe
│   └── file2.txt
└── Variant_B/
    └── file3.com
```

**Output:** Thư mục `samples/` + file `manifest.json`

---

## Phase 2: Phân Tích Tĩnh (Analysis)

**File:** `scr/phase3_analyzer.py`

**Mục tiêu:** Trích xuất đặc trưng từ mỗi file.

**Cách hoạt động:**

```
Với mỗi file:
├── 1. Đọc toàn bộ file vào memory
├── 2. Trích xuất Strings
│   ├── ASCII strings (độ dài ≥ 6)
│   ├── Unicode strings (UTF-16LE)
│   ├── Hex strings
│   ├── Base64 strings
│   └── Reversed strings (đảo ngược)
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
│   └── Headers (Machine, ImageBase...)
├── 5. Trích xuất Opcodes (nếu là PE)
│   ├── Disassemble 1024 bytes từ Entry Point
│   └── Tạo opcode n-grams
```

**Output:** File `analysis_results.json` chứa tất cả features

---

## Phase 3: Tổng Hợp Features (Synthesis)

**File:** `scr/phase4_feature_systhesis.py`

**Mục tiêu:** Tìm features chung và lọc whitelist.

**Cách hoạt động:**

```
1. Kiểm tra whitelist databases
   └── Nếu chưa có → Tự động tải từ GitHub

2. Load whitelist vào memory
   ├── good-strings-*.db (~12M strings)
   └── good-opcodes-*.db (~32M opcodes)

3. Với mỗi loại feature:
   ├── Đếm số lần xuất hiện trong các mẫu
   ├── Tính frequency = count / total_samples
   ├── Lọc theo min_frequency (mặc định 0.7)
   └── Lọc bỏ features trong whitelist

4. Sắp xếp theo frequency giảm dần
```

**Logic lọc:**
```
if frequency < min_frequency → Bỏ qua
if value in whitelist → Bỏ qua
```

**Output:** File `features.json` chứa features đã lọc

---

## Phase 4: Sinh Luật YARA (Generation)

**File:** `scr/phase6_yara_generator.py`

**Mục tiêu:** Tạo các luật YARA từ features.

**Cách hoạt động:**

```
Với mỗi loại feature → Tạo 1 rule:

1. String Rules
   ├── ASCII + Unicode strings (freq ≥ 0.5)
   ├── Loại bỏ patterns chung (đường dẫn, URL...)
   └── Condition: "N of them"

2. Hex String Rules
   ├── Hex-encoded strings (freq ≥ 0.7)
   └── Condition: "N of them"

3. Base64 Rules
   ├── Base64 patterns (freq ≥ 0.6)
   └── Condition: "any of them"

4. Reversed String Rules
   ├── Reversed strings (freq ≥ 0.7)
   └── Condition: "N of them"

5. Import Rules
   ├── Characteristic imports (freq ≥ 0.4)
   └── Condition: "any of them"

6. Opcode Rules
   ├── Opcode patterns (freq ≥ 0.4)
   └── Condition: "any of them"

7. Composite Rules
   ├── High entropy rule (nếu avg > 6.5)
   └── PE header rule (kiểm tra MZ signature)
```

**Metadata mỗi rule:**
- description, author, date
- type (string_based, import_based...)
- confidence (high/medium)
- family name
- source files

**Output:** File `{family}.yar` + `metadata.json`

---

## Luồng Dữ Liệu Hoàn Chỉnh

```
┌─────────────────────────────────────────────────────────┐
│ Input: /path/to/malware/samples                         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 1: MalwareCollector                                │
│ • Copy files to output/samples/                         │
│ • Calculate hashes                                      │
│ • Detect file type                                      │
│ Output: samples/ + manifest.json                         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 2: StaticAnalyzer                                 │
│ • Extract strings, hex, base64, reversed               │
│ • Calculate entropy                                     │
│ • Analyze PE (imports, exports, sections...)           │
│ • Extract opcodes                                       │
│ Output: analysis_results.json                           │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 3: FeatureSynthesizer                             │
│ • Load whitelist (auto-download if missing)            │
│ • Count frequency per feature                           │
│ • Filter by min_frequency + whitelist                  │
│ Output: features.json                                   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Phase 4: YARAGenerator                                  │
│ • Generate string/hex/base64/reversed rules             │
│ • Generate import/opcode rules                         │
│ • Generate composite rules                              │
│ Output: {family}.yar + metadata.json                   │
└─────────────────────────────────────────────────────────┘
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
| `--input-dir` | Thư mục đầu vào | Required |
| `--min-freq` | Tần suất tối thiểu (0.3-1.0) | 0.7 |
| `--output` | Thư mục output | ./output |
| `--dbs-dir` | Thư mục whitelist | ./dbs |
