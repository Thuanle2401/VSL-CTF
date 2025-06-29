# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Evil Service
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Solution

### Mô tả đề bài
- Chương trình cung cấp hai chức năng:
  - Sign Your Message: Nhập vào một thông điệp, server sẽ trả về hash(xor(message, FLAG))
  - Check Your Signature: Nhập một message và một hash, nếu hash(xor(message, FLAG)) == hash → trả về "Validated!"

- Vấn đề: FLAG là một chuỗi bí mật được XOR với message đầu vào, sau đó được băm bằng SHA-256. Người dùng không biết FLAG, nhưng có thể dùng chức năng (1) và (2) để gửi message tuỳ ý và kiểm tra kết quả.

### Ý tưởng khai thác
- Nhận xét quan trọng
- Giả sử:

```ini
h = sha256(xor(message, FLAG))
```

- Với:
  - Bạn kiểm soát message
  - hash() và xor() là hàm xác định và dễ mô phỏng
  - sha256(xor(m, FLAG)) là kết quả mà bạn có thể gửi vào để được “Validated”

- Điều này biến chương trình thành một signature oracle, nơi bạn có thể xác thực (Check) bao nhiêu lần cũng được.

### Mục tiêu
- Tìm được FLAG, mặc dù:
  - Không biết trước nội dung
  - Không thể truy cập trực tiếp

### Cách khai thác: Dò FLAG từng byte
- Nếu bạn gửi message = b'\x00' * len(FLAG), thì:

```perl
xor(message, FLAG) = FLAG
```

→ sha256(FLAG) = H
- Nhưng ta không biết len(FLAG) và cũng không thể gửi toàn bộ message đúng trong 1 lần.

- Vậy ta sẽ:
  - Dò từng ký tự trong FLAG, từ đầu đến cuối
  - Với mỗi ký tự, gửi Check Signature với:
  - message = flag_đã_dò + thử_1_ký_tự + b'\x00' * phần_còn_lại

- hash = sha256(b'\x00' * len(message))

--> Khi server trả về "Validated!" → ký tự đúng

### Khai thác thực tế (Code)
```python
from pwn import *
from hashlib import sha256

r = remote('61.14.233.78', 9000)

flag = ""
checkHash = b"\x00"

while True:
    for i in range(33, 126):  # Printable ASCII
        r.recvuntil(b"$ ")
        r.sendline(b"2")  # Chọn "Check Signature"
        r.recvuntil(b"$ ")
        
        checkFlag = flag + chr(i)
        
        r.sendline(checkFlag.encode())  # Gửi message
        r.recvuntil(b"$ ")
        
        hashed = sha256(checkHash).digest().hex()
        r.sendline(hashed.encode())  # Gửi hash ứng với FLAG bị XOR bằng b'\x00'
        
        response = r.recvline().decode()
        
        if "Validated" in response:
            flag += chr(i)
            checkHash += b"\x00"  # Mở rộng checkHash thêm 1 byte (vì SHA-256 cần full độ dài)
            print("Flag now: " + flag)
            if "}" in flag:
                print("Flag: " + flag)
                exit()
            break
```

- Giải thích dòng logic
  - checkHash ban đầu là 1 byte \x00
  - Mỗi lần đoán đúng một ký tự → mở rộng checkHash thêm \x00 (tương ứng với message mới dài hơn)
  - Vì xor(message, FLAG) và message đều tăng độ dài → phải giữ hash đầu vào phù hợp

- Tại sao khai thác được?
  - Không có kiểm tra độ dài message khớp với FLAG
  - Người dùng có thể gửi message tuỳ ý và nhận lại kết quả hash → Signature Oracle
  - Không có randomization hay salt → dễ dàng đoán từng byte

### Kết quả
- Chạy script và nhận được:

```yaml
Flag now: V
Flag now: VS
...
Flag: VSL{5b81f91f3c4b64e8cf84417ff678c3e6}
```