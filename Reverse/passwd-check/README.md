# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Passwd Check
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin Challenge:
- [Link Download](https://vsl.ce.vku.udn.vn/files/7caf9e7f2210db16396a1490eb6bb78b/passwd_check.zip?token=eyJ1c2VyX2lkIjoyMDgsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjQ1fQ.aFXocg.t8CyLTQHblf8ub4Lqws0v8IzjuY)
- Mô tả thử thách: 
<pre>
Lại là @ph4n10m đây. Có lẻ mùa hè đã quá khắc nghiệt với cậu ấy. Một mật khẩu mới, phức tạp hơn nữa. Tuy nhiên, sự đãng trí lại hành hạ @ph4n10m.
Hãy giúp cậu ấy lại nhé!
Format flag: VSL{password}
</pre>

## 3. Solution:
- Công cụ hỗ trợ: **IDA free 9.0**

### 3.1. Xác định mục tiêu
- Phân tích một binary ELF và trích xuất được password đúng để vượt qua kiểm tra ("You win!"), dựa trên phân tích từ các hàm khởi tạo và xác thực trong chương trình.

### 3.2. Phân tích điểm vào (start)
```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  _UNKNOWN *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_402270(
    (unsigned int)sub_401DE7,
    v4,
    (unsigned int)&retaddr,
    (unsigned int)sub_402C40,
    (unsigned int)sub_402CD0,
    a3,
    (__int64)&v5);
  __halt();
}
```
- Chương trình bắt đầu từ hàm `start`, có prototype như sau:

```c
void __fastcall __noreturn start(__int64 a1, __int64 a2, __int64 a3)
```
- Entrypoint (_start) – nơi thiết lập môi trường chương trình.
- Từ đây, ta có thể xác định:
	+ `sub_401DE7` chính là `main`
	+ `sub_402C40` và `sub_402CD0` là các hàm khởi tạo/giải phóng
	+ `sub_402270` là một wrapper tương đương `__libc_start_main`

### 3.3. Tìm hàm kiểm tra mật khẩu
- Thông qua `main`, ta phát hiện một hàm đáng ngờ `sub_401CAD` có vẻ như được dùng để kiểm tra đầu vào:
```c
__int64 __fastcall sub_401CAD(__int64 a1)
{
  _WORD v2[22]; // [rsp+8h] [rbp-30h]
  int i; // [rsp+34h] [rbp-4h]

  v2[0] = word_4CA174;
  v2[1] = word_4CA17A;
  v2[2] = word_4CA10A;
  v2[3] = word_4CA16C;
  v2[4] = word_4CA134;
  v2[5] = word_4CA17C;
  v2[6] = word_4CA16A;
  v2[7] = word_4CA178;
  v2[8] = word_4CA13A;
  v2[9] = word_4CA16E;
  v2[10] = word_4CA170;
  v2[11] = word_4CA174;
  v2[12] = word_4CA136;
  v2[13] = word_4CA17E;
  v2[14] = word_4CA124;
  v2[15] = word_4CA120;
  v2[16] = word_4CA172;
  v2[17] = word_4CA138;
  v2[18] = word_4CA174;
  v2[19] = word_4CA172;
  v2[20] = word_4CA13C;
  v2[21] = 0;
  for ( i = 0; i <= 21; ++i )
  {
    if ( *(char *)(i + a1) != (unsigned __int16)v2[i] )
      return 0LL;
  }
  return 1LL;
}
```
- Hàm này:
	+ Tạo một mảng `v2[22]` gồm các ký tự bí mật từ `.data`
	+ So sánh từng ký tự với dữ liệu người dùng nhập (`a1`)
	+ Trả về `1` nếu đúng hoàn toàn, ngược lại trả về `0`

### 3.4 Khôi phục chuỗi bí mật
- Dữ liệu `.data` các giá trị `word_4CAxxx` được lấy tự **IDA**:
<pre>
data:00000000004CA10A word_4CA10A     dw 46h 
data:00000000004CA120 word_4CA120     dw 51h  
.data:00000000004CA124 word_4CA124     dw 53h     
.data:00000000004CA134 word_4CA134     dw 61h                  ; DATA XREF: sub_401CAD+34↑r
.data:00000000004CA136 word_4CA136     dw 62h                  ; DATA XREF: sub_401CAD+8C↑r
.data:00000000004CA138 word_4CA138     dw 63h                  ; DATA XREF: sub_401CAD+C3↑r
.data:00000000004CA13A word_4CA13A     dw 64h                  ; DATA XREF: sub_401CAD+60↑r
.data:00000000004CA13C word_4CA13C     dw 65h                  ; DATA XREF: sub_401CAD+E4↑r
.data:00000000004CA16A word_4CA16A     dw 31h                  ; DATA XREF: sub_401CAD+4A↑r
.data:00000000004CA16C word_4CA16C     dw 32h                  ; DATA XREF: sub_401CAD+29↑r
.data:00000000004CA16E word_4CA16E     dw 33h                  ; DATA XREF: sub_401CAD+6B↑r
.data:00000000004CA170 word_4CA170     dw 34h                  ; DATA XREF: sub_401CAD+76↑r
.data:00000000004CA172 word_4CA172     dw 35h                  ; DATA XREF: sub_401CAD+B8↑r
.data:00000000004CA174 word_4CA174     dw 36h                  ; DATA XREF: sub_401CAD+8↑r
.data:00000000004CA178 word_4CA178     dw 38h                  ; DATA XREF: sub_401CAD+55↑r
.data:00000000004CA17A word_4CA17A     dw 39h                  ; DATA XREF: sub_401CAD+13↑r
.data:00000000004CA17C word_4CA17C     dw 2Bh                  ; DATA XREF: sub_401CAD+3F↑r
.data:00000000004CA17E word_4CA17E     dw 2Fh  
</pre>

- Ta ánh xạ các giá trị `word_4CAxxx` thành ký tự `ASCII`:

| v2\[i]  | Giá trị hexa | ASCII |
| ------- | ------------ | ----- |
| v2\[0]  | `0x36`       | `'6'` |
| v2\[1]  | `0x39`       | `'9'` |
| v2\[2]  | `0x46`       | `'F'` |
| v2\[3]  | `0x32`       | `'2'` |
| v2\[4]  | `0x61`       | `'a'` |
| v2\[5]  | `0x2B`       | `'+'` |
| v2\[6]  | `0x31`       | `'1'` |
| v2\[7]  | `0x38`       | `'8'` |
| v2\[8]  | `0x64`       | `'d'` |
| v2\[9]  | `0x33`       | `'3'` |
| v2\[10] | `0x34`       | `'4'` |
| v2\[11] | `0x36`       | `'6'` |
| v2\[12] | `0x62`       | `'b'` |
| v2\[13] | `0x2F`       | `'/'` |
| v2\[14] | `0x53`       | `'S'` |
| v2\[15] | `0x51`       | `'Q'` |
| v2\[16] | `0x35`       | `'5'` |
| v2\[17] | `0x63`       | `'c'` |
| v2\[18] | `0x36`       | `'6'` |
| v2\[19] | `0x35`       | `'5'` |
| v2\[20] | `0x65`       | `'e'` |

---> Password: `69F2a+18d346b/SQ5c65e`

- Ta thử chạy chương trình và kiểm tra:
```shell
$ ./passwd_check
Please input the password
69F2a+18d346b/SQ5c65e
You win!
```

- FLAG: `VSL{69F2a+18d346b/SQ5c65e}`





