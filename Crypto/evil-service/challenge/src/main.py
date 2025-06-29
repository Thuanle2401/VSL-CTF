from hashlib import sha256
from secret import FLAG


def menu():
    print("1) Sign Your Message")
    print("2) Check Your Signature")
    print("0) Exit")


def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


def hash(m):
    return sha256(m).digest()


def main():
    print("Welcome to VKU's leading security service. \nI don't believe you can destroy it or do anything with it hahahahahaha (Smile gradually loses its humanity 😈😈)")

    while True:
        try:
            menu()
            choice = int(input("$ "))
        except:
            print("Choose a valid option! Try again.")
            continue

        if choice == 1:
            print("> Enter your message")
            message = input("$ ").encode()
            hashed = hash(xor(message, FLAG))
            print(f"=> Hash: {hashed.hex()}")
            
        elif choice == 2:
            print("> Enter your message")
            message = input("$ ").encode()
            print("Enter your hash: ")
            
            hashed = input("$ ")
            if hash(xor(message, FLAG)).hex() == hashed:
                print("[+] Signature Validated!\n")
            else:
                print(f"[!] Invalid Signature!\n")
        else:
            print("Byeeee")
            exit(0)

if __name__ == "__main__":
    main()