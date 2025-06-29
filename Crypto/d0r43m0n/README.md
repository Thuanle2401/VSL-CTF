# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: d0r43m0n
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Solution

### Mở đầu

Nhận được file `d0r43m0n.zip`, mình giải nén và thấy 3 file:

- `source.py`: mã nguồn mã hóa flag
- `secret.py`: chứa `MASTER_KEY` và `FLAG` (bản giả)
- `output.txt`: chứa ciphertext và password đã được sinh ra

Mình bắt đầu bằng cách phân tích `source.py` để hiểu quá trình mã hóa.

### Phân tích mã nguồn

Đoạn mã chính yếu là:

```python
def generate_password():
    master_key = int.from_bytes(MASTER_KEY, 'little')
    password = ''
    while master_key:
        bit = master_key & 1
        if bit:
            password += random.choice(ALPHABET[:len(ALPHABET)//2])
        else:
            password += random.choice(ALPHABET[len(ALPHABET)//2:])
        master_key >>= 1
```

- Điều thú vị ở đây là:
    - MASTER_KEY được chuyển sang số nguyên (little endian)
    - Mỗi bit trong key sẽ ảnh hưởng đến cách chọn ký tự cho password:
    - Bit 1 → chọn ký tự ngẫu nhiên từ nửa đầu của ALPHABET.
    - Bit 0 → chọn từ nửa sau.

--> Tức là password đang tiết lộ dãy bit của key, dù ký tự cụ thể là ngẫu nhiên.

### Kế hoạch giải

- Mình nhận thấy:
    - Mỗi ký tự trong password cho biết bit tương ứng trong MASTER_KEY.
    - Dựa vào đó, mình có thể khôi phục lại dãy bit → chuyển về MASTER_KEY (dạng bytes).
    - Tạo khóa AES bằng SHA256(MASTER_KEY) → đúng như mã nguồn.
    - Giải mã ciphertext (Encrypted Flag) bằng AES-ECB.

### Khôi phục key và giải mã
- Các bước mình làm:
  - Phân tích password để lấy bit:
  - Nếu ký tự ∈ nửa đầu bảng chữ (ascii_letters + digits) → bit = 1
  - Nếu ∈ nửa sau (~!@#$%^&*) → bit = 0
  - Từ chuỗi bit → tạo lại số nguyên → rồi .to_bytes(..., 'little') để lấy lại MASTER_KEY.
- Tạo AES key:
```python
aes_key = sha256(master_key).digest()
cipher = AES.new(aes_key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(b64decode(ciphertext)), 16)
```
### Script Python
```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode
import string

# Dữ liệu đầu vào
password = "UxcWc8uXFk4%b~IR0NAz54kLDwcIo0IYj^hkNwHL7RfZizOQly3Zykm*&9cXuCx*s@F5WlG!&GV&zneOvzgeGYt3IdUw1PD%p&vS#voUy5Yadfq!seHfz5hOhWFQvzM6Whj3gaRQ$p8Mbx&&xOXDIC%MqvNOCgQ*2Z!1uE"
ciphertext_b64 = "BFw5r152xU41dF4v3j6QrSBWYJUrwulo/dlvvdW8FrOgo2KZdmOmmAeRoHylDcvn"

ALPHABET = string.ascii_letters + string.digits + '~!@#$%^&*'
half = len(ALPHABET) // 2

# Lấy bit từ password
bits = []
for c in password:
    if c in ALPHABET[:half]:
        bits.append(1)
    elif c in ALPHABET[half:]:
        bits.append(0)
    else:
        raise ValueError(f"Unknown character: {c}")

# Tạo lại master_key từ bit
master_key_int = 0
for i, bit in enumerate(bits):
    if bit:
        master_key_int |= (1 << i)

master_key = master_key_int.to_bytes((master_key_int.bit_length() + 7) // 8, 'little')

# Tạo AES key và giải mã
key = sha256(master_key).digest()
cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(b64decode(ciphertext_b64)), 16)

print("Recovered FLAG:", plaintext.decode())
```

### Kết quả
Sau khi chạy script, mình nhận được:
```css
Recovered FLAG: VSL{d0r43m0n_1s_4_l0v3ly_c0d3r_!_@_#_&}
```