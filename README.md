# Auto-YARA Generator

Tự động sinh luật YARA từ mẫu malware cùng họ (family).

## Tính năng

- Thu thập mẫu malware từ thư mục do người dùng cung cấp
- Phân tích tĩnh (strings, imports, PE metadata, entropy, opcodes)
- Lọc whitelist sử dụng yarGen databases từ thư mục `dbs/`
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
| `--input-dir` | Thư mục chứa mẫu malware | Required |
| `--min-freq` | Tần suất tối thiểu (0.3-1.0) | 0.7 |
| `--output` | Thư mục output | ./output |
| `--dbs-dir` | Thư mục chứa whitelist databases | ./dbs |

## Cấu trúc thư mục mẫu

```
malware_samples/
├── Ransomware.WannaCry/
│   ├── sample1.exe
│   └── sample2.exe
├── Ransomware.WannaCry_Plus/
│   └── sample3.exe
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

Lần đầu chạy pipeline, nếu thư mục `dbs/` chưa có databases, chương trình sẽ tự động tải yarGen whitelist databases về (~400MB).

Whitelist được load từ thư mục `dbs/`:
- **good-strings-*.db**: Strings từ phần mềm lành tính
- **good-opcodes-*.db**: Opcodes từ phần mềm lành tính

Tải databases từ: https://github.com/Neo23x0/yarGen-dbs
