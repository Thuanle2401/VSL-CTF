# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Passwd Check
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin Challenge:
- [Link Download](https://vsl.ce.vku.udn.vn/files/cfcf6c24df91ceece5b46cf2014e6595/easy_math.zip?token=eyJ1c2VyX2lkIjoyMDgsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjQ2fQ.aFYAaQ.spclcE-Q1FfAgWC2dvZlO95IpOA)
- Mô tả thử thách: 
<pre>
Một newbie tài năng trong mảng dịch ngược vừa viết ra một chương trình đơn giản. Đáng tiếc thay, cậu ta đã quá ngạo mạn để đi thách thức @ph4n10m crack được chương trình đấy.
@ph4n10m tin bạn giúp được orz
Flag Format: VSL{correct_user_input}
</pre>

## 3. Solution:
- Công cụ: **IDA free 9.0**

### 3.1. Xác định mục tiêu:
- Dưới đây là mã C của chương trình được IDA dịch ngược từ file nhị phân của chương trình:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+8h] [rbp-18h] BYREF
  __int64 v5; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v5 = 0xDEADC0DELL;
  __isoc99_scanf("%lld", &v4);
  v4 ^= 0x1337CAFEuLL;
  if ( v5 == v4 )
    puts("Correct!");
  else
    puts("Wrong");
  return 0;
}
```
- Từ mã C trên, ta cần nhập một giá trị sao cho chương trình in ra:
```output
Correct!
```
### 3.2. Phân tích logic
- Chương trình nhận một số nguyên `v4_input`, rồi `XOR` với `0x1337CAFE`, nếu kết quả bằng `0xDEADC0DE` thì đúng.

- Công thức:
```
(v4_input ^ 0x1337CAFE) == 0xDEADC0DE
```
- Áp dụng tính chất của XOR:

```ini
v4_input = 0xDEADC0DE ^ 0x1337CAFE
```
- Giải bằng Python
```python
v5 = 0xDEADC0DE
xor_key = 0x1337CAFE

v4_input = v5 ^ xor_key
print("Giá trị cần nhập:", v4_input)
```
Kết quả:
```
Giá trị cần nhập: 3449424416
```

### Tính chất của XOR:

```mathematica
A ^ B = C  <=>  A = C ^ B  <=>  B = A ^ C
```