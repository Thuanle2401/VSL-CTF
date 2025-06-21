# VSL Summer CTF

<img src="https://github.com/Thuanle2401/VSL-CTF/blob/main/UploadFile1/images/VSL-summer.png?raw=true" width="500" height="300">

---
# Challenge: Beach Store - PWN
---
## 1. Thông tin người thực hiện
- Họ và tên: Lê Ngọc Thuận

## 2. Thông tin Challenge:
- [Link Download Source Code](https://vsl.ce.vku.udn.vn/files/4d5fad4c539900d689dae9faffa3a13e/summerStore.rar?token=eyJ1c2VyX2lkIjoyMDgsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjQ4fQ.aFYUbw.2aoxeUOD9wD__yb6ZNULWFggWe4)

- Netcat connection: `nc 61.14.233.78 7003`

## 3. Solution
- Mô tả thử thách: 
	+ Khi chạy chương trình, ta sẽ được cung cấp một menu gồm các vật phẩm, giá thành của từng sản phẩm và túi tiền mà chương trình cấp cho người dùng `30$`. 
    + Trong các sản phẩm này ta có một sản phẩm là FLAG với giá `1000000$` có lẽ mục tiêu của ta là cố gắng mua được FLAG.
    
- Phân tích file `source.c`:

```c
switch (id)
            {
            case 1:
                printf("Enter amount: ");
                fflush(stdout);

                if (scanf("%d", &amount) != 1)
                {
                    puts("Invalid amount\n");
                    break;
                }
                if (check_money(10 * amount))
                {
                    printf("You bought %d Star\n", amount);
                    money -= 10 * amount;
                }
                else
                {
                    puts("You don't have enough money\n");
                }
                break;
           ....
```
- Sau khi ta chọn mua vật phẩm đầu tiên `Swimming goggles` chương trình sẽ yêu cầu ta nhập số lượng: `if (scanf("%d", &amount) != 1)`, nhưng có một điều kì lạ là chương trình không validate biến `amount` và sẽ ra sao nếu ta nhập số lượng âm (ở đây ta sẽ thử nhập `-1000000`)
- Chương trình sẽ tiếp tục đi xuống hàm `if` thứ hai để kiểm tra liệu ta có đủ tiền mua sản phẩm với số lượng là `-1000000` hay không và lúc này ta sẽ thử quan sát hàm `check_money()`:
```c
int check_money(int price)
{
    if (money >= price)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
```

- Biến `price` sẽ có giá trị là: `10 * amount` vậy thỏa mãn `if (money >= price)` (`money` ban đầu của ta là: `30$`)

- Vậy tiếp tục chương trình sẽ thực hiện gán: `money -= 10 * amount` và `money` của ta lại được tăng thêm, tổng: `10000030$`

- Lúc này ta đã có thể mua được Flag `1000000$`:
```bash
==================================
This is our store's product table
==================================
Your cash: 10000030
|-----------------------------------------------------|
| ID ---------- Product          ----------     Price |
|-----------------------------------------------------|
|  1 ---------- Swimming goggles ----------       10$ |
|  2 ---------- Swimwear         ----------       15$ |
|  3 ---------- Flag             ----------  1000000$ |
|-----------------------------------------------------|
1. Buy

2. Back to menu

Your choice: 1
Enter your product id: 3
Congratulation. Have a cool summer, here is your flag:
VSL{4_funny_st0r3_1n_summ3r_202mfj2%2!@4jf}
```
- FLag: **VSL{4_funny_st0r3_1n_summ3r_202mfj2%2!@4jf}**
    
