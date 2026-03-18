# Auto-YARA Generator

Tự động sinh luật YARA từ mẫu malware cùng họ (family).

## Tính năng

- Thu thập mẫu malware từ thư mục
- Phân tích tĩnh (strings, imports, PE metadata, entropy, opcodes)
- Lọc whitelist sử dụng yarGen databases (12M+ strings, 32M+ opcodes)
- Sinh luật YARA với metadata và source tracking

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

### 3. Download yarGen databases (tự động)
Lần đầu chạy pipeline sẽ tự động download databases (~400MB).

## Sử dụng

### Chạy pipeline cơ bản
```bash
source venv/bin/activate
python main.py --family WannaCry --source directory --input-dir /path/to/malware samples/
```

### Tùy chọn đầy đủ
```bash
python main.py \
    --family "Ransomware.WannaCry" \
    --source directory \
    --input-dir /data/samples/WannaCry \
    --min-freq 0.7 \
    --output-dir ./output
```

### Tham số

| Tham số | Mô tả | Mặc định |
|---------|-------|-----------|
| `--family` | Tên malware family | Required |
| `--source` | Loại nguồn (`directory`) | directory |
| `--input-dir` | Thư mục chứa mẫu malware | Required |
| `--min-freq` | Tần suất tối thiểu (0.0-1.0) | 0.7 |
| `--output-dir` | Thư mục output | ./output |
| `--dbs-dir` | Thư mục yarGen databases | ./dbs |

## Cấu trúc thư mục mẫu

```
malware_samples/
├── Ransomware.WannaCry/
│   ├── sample1.exe
│   └── sample2.exe
├── Ransomware.WannaCry_Plus/
│   └── sample3.exe
└── ...
```

## Output

Luật YARA được lưu tại `output/<family_name>.yar`:
```yara
rule WannaCry_strings {
    meta:
        description = "Auto-generated rule for WannaCry - strings"
        family = "WannaCry"
        source_files = "sample1.exe, sample2.exe"
    strings:
        $s0 = "specific_string" ascii wide // Found in: 2 files
    condition:
        any of them
}
```

## Database

- **yarGen whitelist**: 44 files từ https://github.com/Neo23x0/yarGen-dbs
- Tự động download lần đầu
- Bao gồm: good-strings, good-opcodes, good-imphashes, good-exports

