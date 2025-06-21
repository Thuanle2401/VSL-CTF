# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Beginner
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin Challenge:
- Mô tả: 
<pre>
@ph4n10m nhận được thông điệp kỳ lạ từ @d4kw1n mà anh ấy không hiểu. Các bạn có thể giúp anh ấy giải mã được không? 
56 6d 30 77 65 45 35 47 55 58 68 56 62 47 68 58 59 57 78 77 57 46 59 77 61 45 4e 56 52 6c 5a 79 56 6d 74 6b 54 6b 31 58 55 6e 70 57 56 33 68 33 56 47 78 4b 56 56 4a 73 57 6c 64 4e 61 6b 56 33 56 6b 52 47 53 31 49 79 54 6b 6c 55 62 46 5a 70 56 30 56 4b 53 46 64 73 5a 48 70 6c 52 30 35 58 55 6d 78 73 61 6c 4a 75 51 6e 42 57 62 47 51 77 54 6c 5a 5a 65 55 31 59 5a 47 6c 68 65 6b 49 7a 56 47 74 6f 63 31 59 79 53 6c 68 6c 52 30 5a 68 56 6e 70 47 63 6c 52 55 52 6e 64 6a 4d 55 70 56 59 6b 5a 47 56 6c 5a 45 51 54 55 3d
</pre>
    
## 3. Solution:
- Thử thách cung cấp cho ta mã `hex` rất có thể khi giải mã xong ta sẽ có được flag.
- Mình sẽ dùng trang Hex decoder:
	+ [Hex decoder online](https://cryptii.com/pipes/hex-decoder)
    + Nội dung sau khi được decode: `Vm0weE5GUXhVbGhXYWxwWFYwaENVRlZyVmtkTk1XUnpWV3h3VGxKVVJsWldNakV3VkRGS1IyTklUbFZpV0VKSFdsZHplR05XUmxsalJuQnBWbGQwTlZZeU1YZGlhekIzVGtoc1YySlhlR0ZhVnpGclRURndjMUpVYkZGVlZEQTU=`

- Ta lại nhận được mã `base64` và mình sẽ tiếp tục decode với trang [Base64 online](https://www.base64decode.org/) 

- Sau khi decode base64 lần đầu thì mình lại nhận được một mã base64 mới, tiếp tục decode cho đến khi nhận được nội dung có định dạng flag và flag mình nhận được là: `VSL{53400e6416d46e613203bb6f877ebc80}`