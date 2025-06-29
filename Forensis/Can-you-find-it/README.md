# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/web/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---

# Challenge: Can you find it ?

---

## 1. Thông tin người thực hiện

- Họ và tên: Lê Ngọc Thuận

## 2. Mô tả thử thách

- Mô tả từ tác giả: @ph4n10m đang vi vu giữa biển trên du thuyền, một chú cá voi xanh xuất hiện và đưa một thông điệp bí mật.

```bash
docker run --rm -it -p 80:80 ph4n10m1808/findit  
```

## 3. Solution

### Bước 1: Chạy `image` theo chỉ dẫn

- Khi chạy container:

```bash
docker run --rm -it -p 80:80 ph4n10m1808/findit
```

- Sau đó, mình có vào thư mục root của server và thấy file `flag.txt` tuy nhiên khi thử đọc và xem kích thước của file thì đây chỉ là một file rỗng.

- Sau khi tìm hiểu về `Docker` thì mình biết được `Docker` lưu trữ `image` theo nhiều `layer` chồng lên nhau. Khi một file bị "xóa" hoặc "ghi đè" trong `layer` sau, nội dung thật sự của nó vẫn tồn tại trong `layer` trước.

--> Vì vậy, ta có thể tải `Docker image` về, giải nén từng `layer`, và tìm lại file `flag.txt` bị ghi đè.

### Bước 2: Lưu `Docker image` thành file `.tar`

```bash
docker save ph4n10m1808/findit > image.tar
```

### Bước 3: Giải nén `Docker image`

```bash
mkdir extract && cd extract
tar -xf ../image.tar
```

- Lúc này sẽ xuất hiện các thư mục như:

```pgsql
blobs/
manifest.json
index.json
oci-layout
```

### Bước 4: Dò tìm `flag.txt` trong các `layer` (`blobs`)

- `Docker OCI format` lưu từng `layer` là 1 file `.tar` trong `blobs/sha256/`. Ta kiểm tra xem `layer` nào có chứa `flag.txt`:

```bash
find blobs/sha256/ -type f -exec tar -tf {} \; 2>/dev/null | grep flag.txt
```

--> Output:

```css
flag.txt
flag.txt
```

--> Có 2 `layer` chứa file `flag.txt`.

### Bước 5: Trích xuất từng `layer` để xem nội dung `flag.txt`

- Chạy đoạn script sau để kiểm tra từng `layer`:

```bash
for f in blobs/sha256/*; do
  mkdir -p tmp
  tar -xf "$f" -C tmp 2>/dev/null
  if [ -f tmp/flag.txt ]; then
    echo -e "\n[+] Found flag.txt in $f"
    echo "[>] Content:"
    cat tmp/flag.txt
  fi
  rm -rf tmp
done
```

### Kết quả:

- Một trong các layer sẽ in ra flag:

```css
[+] Found flag.txt in blobs/sha256/0c0483b597a3b1175e0c760cdfe2af7dd2a2edce1dfb852471c96d96b874057f
[>] Content:
VSL{b91ea3e8285157eaf173d88d0a73ed5a}
```

### Kết luận

- Docker lưu image theo nhiều layer.
- Khi một file bị ghi đè hoặc xóa trong layer mới, ta vẫn có thể lục lại trong layer cũ.
- Bằng cách giải nén image, duyệt qua các layer và kiểm tra file bị "che", ta có thể thu lại flag bị ẩn.
