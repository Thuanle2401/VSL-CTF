import random
import time
from secret import FLAG

MAX = 2**32-1
menu = """
__     __ ____   _       _____  _                           ____
\ \   / // ___| | |     |_   _|(_) _ __ ___    ___         / ___|  ___   _ __
 \ \ / / \___ \ | |       | |  | || '_ ` _ \  / _ \ _____ | |     / _ \ | '_ \\
  \ V /   ___) || |___    | |  | || | | | | ||  __/|_____|| |___ | (_) || |_) |
   \_/   |____/ |_____|   |_|  |_||_| |_| |_| \___|        \____| \___/ | .__/
                                                                        |_|

====================== M E N U ======================

1. Get time proof
2. Set time
3. Exit

=====================================================
""".strip()


def timeNow(input):
    timeSecret = []
    
    for char in input:
        randomNumber = random.randint(0, MAX)
        encChar = (char + randomNumber) % 256
        timeSecret.append(encChar)
        
    return int(bytes(timeSecret).hex(), 16)

def main():
    seed = int(time.time())
    
    random.seed(seed)
    
    while 1:
        print(menu)
        t = input("> Your Input: ").strip()

        if t == "1":
            enc = timeNow(FLAG)
            print("Evidence of time: %s" % enc)
            
        elif t == "2":
            seed = int(time.time())
            random.seed(seed)
            print("The time has been set")
        else:
            print("""
 ____  __   __ _____  _  _
| __ ) \ \ / /| ____|| || |
|  _ \  \ V / |  _|  | || |
| |_) |  | |  | |___ |_||_|
|____/   |_|  |_____|(_)(_)
                  """)
            exit()


if __name__ == '__main__':
    main()