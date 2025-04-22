from random import randbytes
import sys
class RC5:

    def __init__(self, w, R, key, strip_extra_nulls=False):
        self.w = w  # block size (32, 64 or 128 bits)
        self.R = R  # number of rounds (0 to 255)
        self.key = key  # key (0 to 2040 bits)
        self.strip_extra_nulls = strip_extra_nulls
        # some useful constants
        self.T = 2 * (R + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)

        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __const(self):  # constants generation
        if self.w == 16:
            return 0xB7E1, 0x9E37  # return P, Q values
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    def __keyAlign(self):
        if self.b == 0:  # key is empty
            self.c = 1
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encryptBlock(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.R + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decryptBlock(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        for i in range(self.R, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def encryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    text = text.ljust(self.w4, b'\x00')
                    run = False
                text = self.encryptBlock(text)
                out.write(text)

    def decryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            while True:
                text = inp.read(self.w4)
                if not text:
                    break
                text = self.decryptBlock(text)
                if self.strip_extra_nulls:
                    text = text.rstrip(b'\x00')
                out.write(text)

    def encryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                data = data.ljust(self.w4, b'\x00')
                run = False
            res += self.encryptBlock(temp)
            data = data[self.w4:]
            if not data:
                break
        return res

    def decryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                run = False
            res += self.decryptBlock(temp)
            data = data[self.w4:]
            if not data:
                break
        return res.rstrip(b'\x00')
    

def encrypt(message:str,block_size=64,key_length=128,round_count=12)->list[bytes,str]:
    key=randbytes(key_length//8)

    rc5 = RC5(block_size, round_count, key)
    res=rc5.encryptBytes(bytes(message,encoding="utf-8"))
       
    return [key.hex(),res.hex()]

def decrypt(message:str,key:bytes,block_size=64,round_count=12)->str:

    rc5 = RC5(block_size, round_count, bytes.fromhex(key))
    res=rc5.decryptBytes(bytes.fromhex(message))
    return res.decode("utf-8")


if __name__ == '__main__':
    type = str(sys.argv[1])  # Takes number from command line argument

    if type=="encrypt":
        key,res=encrypt(sys.argv[2])
        print(key,res)
    else:
        res=decrypt(sys.argv[2],sys.argv[3])
        print(res)
    sys.stdout.flush()


# key=randbytes(128//8)



# rc5 = RC5(64, 12, key)
# res=rc5.encryptBytes(bytes("Deneme mesaji",encoding="utf-8")).hex()
# original=rc5.decryptBytes(bytes.fromhex(res))
# print(res)
# print(original.decode("utf-8"))
# print("Original",res)
# string=str(res)
# tmp=bytes.fromhex(str(res))
# print(rc5.decryptBytes(tmp).decode("utf-8"))