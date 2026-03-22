# Auto-YARA Generator

Tự động sinh luật YARA từ mẫu malware cùng họ (family).

## Tính năng

- Thu thập mẫu malware từ thư mục do người dùng cung cấp (mỗi subdirectory = 1 variant)
- Phân tích tĩnh (strings, imports, PE metadata, entropy, opcodes)
- Lọc whitelist sử dụng yarGen databases (~12M strings, ~34M opcodes)
- String scoring với ~60 patterns như yarGen
- Super Rules (gộp strings từ nhiều variants)
- 80% threshold cho condition
- Auto-download whitelist databases nếu chưa có

## Yêu cầu

```bash
# Tạo virtual environment
python3 -m venv venv

# Kích hoạt
source venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt
```

## Cài đặt

### 1. Clone project
```bash
git clone <repo-url>
cd PhanTichMaDoc
```

### 2. Tạo virtual environment và cài đặt
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Chạy pipeline
Lần đầu chạy, nếu chưa có whitelist databases trong thư mục `dbs/`, pipeline sẽ tự động tải về (~400MB).

## Sử dụng

### Chạy pipeline
```bash
source venv/bin/activate
python main.py \
    --family "Ransomware.WannaCry" \
    --input-dir /path/to/malware/samples \
    --min-freq 0.7 \
    --output ./output \
    --dbs-dir ./dbs
```

### Tham số

| Tham số | Mô tả | Mặc định |
|---------|-------|-----------|
| `--family` | Tên malware family | Required |
| `--input-dir` | Thư mục chứa mẫu malware (mỗi subdirectory = 1 variant) | Required |
| `--min-freq` | Tần suất tối thiểu (0.3-1.0) | 0.7 |
| `--output` | Thư mục output | ./output |
| `--dbs-dir` | Thư mục chứa whitelist databases | ./dbs |

## Cấu trúc thư mục mẫu (bắt buộc)

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

**Lưu ý:** Mỗi subdirectory = 1 variant của malware family.

## Output

Luật YARA được lưu tại `output/<family_name>.yar`:

```yara
import "pe"

rule WannaCry_strings {
    meta:
        description = "Auto-generated rule for WannaCry - strings"
        author = "AutoYaraGen"
        date = "2026-03-22"
        type = "string_based"
        confidence = "high"
        family = "WannaCry"
        source_files = "Variant_A, Variant_B"
    strings:
        $s0 = "specific_string1" ascii wide
        $s1 = "specific_string2" ascii wide
        // ... 18 strings nữa
    condition:
        (16 of them) and filesize > 1MB and filesize < 10MB
}

rule WannaCry_imphash {
    meta:
        description = "Auto-generated rule for WannaCry - imphash"
        family = "WannaCry"
    condition:
        pe.imphash() == "68f013d7437aa653a8a98a05807afeb1"
}
```

## Database

Lần đầu chạy pipeline, nếu thư mục `dbs/` chưa có databases, chương trình sẽ tự động tải yarGen whitelist databases về (~400MB).

Whitelist được load từ thư mục `dbs/`:
- **good-strings-*.db**: ~12M strings từ phần mềm lành tính
- **good-opcodes-*.db**: ~34M opcodes từ phần mềm lành tính
- **good-imphashes-*.db**: ~19K imphashes từ phần mềm lành tính
- **good-exports-*.db**: ~404K exports từ phần mềm lành tính

Tải databases từ: https://github.com/Neo23x0/yarGen-dbs

## Các Loại Rules Được Sinh

| Rule Type | Mô tả | Condition |
|-----------|-------|-----------|
| `strings` | ASCII + Unicode strings | 80% of them + filesize |
| `hex_strings` | Hex-encoded strings | 80% of them + filesize |
| `base64` | Base64 patterns | any of them + filesize |
| `reversed` | Reversed strings | 80% of them + filesize |
| `imports` | PE imports | 80% of them |
| `opcodes` | Opcode patterns | 80% of them |
| `imphash` | Import hash | pe.imphash() == "..." |
| `ep_bytes` | Entry point bytes | at pe.entry_point |
| `super` | Strings chung từ ≥2 variants | 80% of them |

