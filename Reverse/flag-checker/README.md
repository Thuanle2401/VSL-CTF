# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: FlagChecker
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin Challenge:
- [Link Download](https://vsl.ce.vku.udn.vn/files/721ce5bfd07dc3be939c14350d859e2e/flagchecker.apk?token=eyJ1c2VyX2lkIjoyMDgsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjQ5fQ.aFYLTw.Vi9Ymfp7uPopCewRetv3Wp5hvGg)

## 3. Solution
- Công cụ: **jadx-gui** và **IDA free 9.0**
### Challenge Overview
- Chúng ta được cung cấp một file APK có tên flagchecker.apk. Khi mở bằng jadx-gui, ta phát hiện ứng dụng sử dụng `Jetpack Compose`, nhưng điều đặc biệt là hàm kiểm tra flag được gọi qua `native library (.so)`, tức là không thể đọc flag trực tiếp từ `Java/Kotlin` code.

### 3.1. Phân tích Java Code bằng JADX
- Trong file `MainActivity.kt`, ta thấy dòng gọi hàm `JNI`:
```java
private native boolean checkFlag(String input);

static {
    System.loadLibrary("native-lib");
}
```
Dòng:
```java
System.loadLibrary("native-lib");
```
→ App sử dụng thư viện native tên `libnative-lib.so`<br>
→ Điều này cho thấy rằng hàm kiểm tra flag thực sự nằm trong file `.so` (thư viện native). Ta sẽ cần phân tích `.so` này (thường nằm trong thư mục lib/ của APK).

- Dùng lệnh để trích xuất `libnative-lib.so`

```bash
unzip flagchecker.apk 'lib/*/libnative-lib.so'
```
- Sau đó dùng **IDA** để phân tích file `libnative-lib.so`.

### 3.2. Tìm hàm `checkFlag` trong IDA
Tên hàm `JNI` theo pattern:
```php-template
Java_<package>_<class>_<method>
```
→ Tìm được hàm:
```c
_BOOL8 __fastcall Java_com_vsl_flagchecker_MainActivity_checkFlag(__int64 env, __int64 thiz, __int64 jstring_input)
```
### 3.3. Phân tích logic trong `checkFlag`
```c
if (strlen(input) == 44) {
    _stop_crypt(input, buffer);
    return memcmp(buffer, unk_740, 44) == 0;
}
```
- Giải thích code:
	+ Kiểm tra độ dài input là 44
	+ Gọi hàm _stop_crypt(input, buffer) để mã hóa
	+ So sánh buffer với chuỗi mã hóa unk_740

→ Mục tiêu: phục hồi lại input gốc sao cho sau khi mã hóa bằng `_stop_crypt` sẽ ra bằng `unk_740`

### 3.4. Dump dữ liệu `unk_740` trong IDA
Từ `.rodata`:
<pre>
rodata:0000000000000740 unk_740         db  56h ; V             ; DATA XREF: Java_com_vsl_flagchecker_MainActivity_checkFlag+CC↓o
.rodata:0000000000000741                 db  9Dh
.rodata:0000000000000742                 db 0B3h
.rodata:0000000000000743                 db  85h
.rodata:0000000000000744                 db 0AFh
.rodata:0000000000000745                 db  7Fh ; 
.rodata:0000000000000746                 db 0A0h
.rodata:0000000000000747                 db  4Bh ; K
.rodata:0000000000000748                 db  83h
.rodata:0000000000000749                 db  49h ; I
.rodata:000000000000074A                 db  76h ; v
.rodata:000000000000074B                 db 0E0h
.rodata:000000000000074C                 db  21h ; !
.rodata:000000000000074D                 db  78h ; x
.rodata:000000000000074E                 db  22h ; "
.rodata:000000000000074F                 db 0EDh
.rodata:0000000000000750                 db  0Eh
.rodata:0000000000000751                 db 0D9h
.rodata:0000000000000752                 db 0FDh
.rodata:0000000000000753                 db 0F5h
.rodata:0000000000000754                 db 0B8h
.rodata:0000000000000755                 db 0B8h
.rodata:0000000000000756                 db 0D8h
.rodata:0000000000000757                 db  1Ah
.rodata:0000000000000758                 db  16h
.rodata:0000000000000759                 db  93h
.rodata:000000000000075A                 db  70h ; p
.rodata:000000000000075B                 db    7
.rodata:000000000000075C                 db  35h ; 5
.rodata:000000000000075D                 db  34h ; 4
.rodata:000000000000075E                 db  27h ; '
.rodata:000000000000075F                 db 0C5h
.rodata:0000000000000760                 db  34h ; 4
.rodata:0000000000000761                 db 0BAh
.rodata:0000000000000762                 db    9
.rodata:0000000000000763                 db  74h ; t
.rodata:0000000000000764                 db 0DAh
.rodata:0000000000000765                 db  68h ; h
.rodata:0000000000000766                 db 0E8h
.rodata:0000000000000767                 db  7Eh ; ~
.rodata:0000000000000768                 db  6Ch ; l
.rodata:0000000000000769                 db  8Bh
.rodata:000000000000076A                 db  9Bh
.rodata:000000000000076B                 db  83h
</pre>

```mathematica
unk_740: 56 9D B3 85 AF 7F A0 4B 83 49 76 E0 21 78 22 ED
         0E D9 FD F5 B8 B8 D8 1A 16 93 70 07 35 34 27 C5
         34 BA 09 74 DA 68 E8 7E 6C 8B 9B 83
```
→ Đây là flag đã mã hóa (44 byte)

### 3.5. Phân tích _stop_crypt
```c
for (i = 0; i < strlen(input); i++) {
    v3 = byte_770[(7 * i) % 0x14];
    output[i] = (v3 >> (i % 5)) ^ rol(byte_770[i % 0x14], (3 * i) & 7) ^ input[i];
}
```
→ Đây là một hàm mã hóa `xor` kết hợp với `rotate bit`, cụ thể:
- `byte_770` là bảng khóa dài 20 byte (từ `.rodata`)
<pre>
.rodata:0000000000000770                                         ; __stop_crypt+83↓o
.rodata:0000000000000771                 db 0DBh
.rodata:0000000000000772                 db 0AFh
.rodata:0000000000000773                 db 0F2h
.rodata:0000000000000774                 db  4Eh ; N
.rodata:0000000000000775                 db 0D0h
.rodata:0000000000000776                 db 0ADh
.rodata:0000000000000777                 db  20h
.rodata:0000000000000778                 db 0D7h
.rodata:0000000000000779                 db 0A0h
.rodata:000000000000077A                 db  18h
.rodata:000000000000077B                 db 0D7h
.rodata:000000000000077C                 db  15h
.rodata:000000000000077D                 db  52h ; R
.rodata:000000000000077E                 db  51h ; Q
.rodata:000000000000077F                 db  7Bh ; {
.rodata:0000000000000780                 db  5Bh ; [
.rodata:0000000000000781                 db  14h
.rodata:0000000000000782                 db  26h ; &
.rodata:0000000000000783                 db 0D1h
.rodata:0000000000000783 _rodata         ends
</pre>

```mathematica
byte_770: 0x84, 0xDB, 0xAF, 0xF2, 0x4E, 0xD0, 0xAD, 0x20,
    	  0xD7, 0xA0, 0x18, 0xD7, 0x15, 0x52, 0x51, 0x7B,
    	  0x5B, 0x14, 0x26, 0xD1
```
- `rol()` là phép xoay bit trái
- Mỗi byte trong input được `XOR` với 2 giá trị tính từ bảng `byte_770`

### 3.6. Viết script giải ngược
- Vì hàm mã hóa là:
```c
output[i] = (v3 >> (i % 5)) ^ rol(byte_770[i % 0x14], (3 * i) & 7) ^ input[i]
```
→ Mã giả ngược:
```python
input[i] = output[i] ^ (v3 >> (i % 5)) ^ rol(...)
```
### Script Python
```python
cipher = bytes([
    0x56, 0x9D, 0xB3, 0x85, 0xAF, 0x7F, 0xA0, 0x4B,
    0x83, 0x49, 0x76, 0xE0, 0x21, 0x78, 0x22, 0xED,
    0x0E, 0xD9, 0xFD, 0xF5, 0xB8, 0xB8, 0xD8, 0x1A,
    0x16, 0x93, 0x70, 0x07, 0x35, 0x34, 0x27, 0xC5,
    0x34, 0xBA, 0x09, 0x74, 0xDA, 0x68, 0xE8, 0x7E,
    0x6C, 0x8B, 0x9B, 0x83
])

byte_770 = [
    0x84, 0xDB, 0xAF, 0xF2, 0x4E, 0xD0, 0xAD, 0x20,
    0xD7, 0xA0, 0x18, 0xD7, 0x15, 0x52, 0x51, 0x7B,
    0x5B, 0x14, 0x26, 0xD1
]

def rol(val, r_bits):
    r_bits %= 8
    return ((val << r_bits) | (val >> (8 - r_bits))) & 0xFF

flag = b""

for i in range(len(cipher)):
    v3 = byte_770[(7 * i) % 0x14]
    part1 = v3 >> (i % 5)
    part2 = rol(byte_770[i % 0x14], (3 * i) & 7)
    plain_char = cipher[i] ^ part1 ^ part2
    flag += bytes([plain_char])

print("Flag:", flag.decode())
```
Flag: **VSL{FlAg_ChEcKeR_MaStEr_UnLoCk_522_ReVeAlEd}**