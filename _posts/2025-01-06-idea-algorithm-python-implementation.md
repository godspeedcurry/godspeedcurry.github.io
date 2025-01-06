---
layout: post
title: IDEA algorithm python implementation
date: 2025-01-06 11:22 +0800
categories: [realworld,crypto]
tag: [crypto]
---

IDEA（International Data Encryption Algorithm）是一种对称密钥密码学算法，由 James Massey 和 Xuejia Lai 于 1991 年设计。它最初被设计为 DES（Data Encryption Standard）的替代品。IDEA 因其对称性和 128 位密钥长度而在 20 世纪 90 年代受到关注。

### 核心特性
* 密钥长度：IDEA 使用一个 128 位密钥。
* 数据分组：64 位分组加密。
* 轮数：总共进行 8.5 轮加密操作。

### 运算基础
* 模 2 的 16 次方加法。
* 模 2 的 16 次方加 1 的乘法。
* 按位异或（XOR）。

### 加密过程
IDEA 算法的加密过程包括以下步骤：

### 轮操作

* 共进行 8 轮基本操作。在每一轮中，将 64 位的数据分组分为四个 16 位的子块。
* 每一轮中，使用 6 个子密钥进行转换操作，具体使用模加、模乘和 XOR 操作。
* 前两块分别与两个密钥做模乘和模加，后两块与剩余两个密钥做 XOR。在所有四个 16 位块之间进行额外的 XOR 和交换操作。
* 第 9 次半轮操作：
进行一次简化操作，称为“半轮”。
这一轮中使用剩余的 4 个密钥进行模乘和模加操作。

### 解密过程
解密过程与加密过程类似，使用生成的解密密钥。这些密钥可以通过加密密钥反向计算获得，步骤相似但顺序和操作互补。

### 密钥生成
IDEA 将输入的 128 位密钥分成 52 个 16 位的子密钥，每轮使用这些子密钥进行加密操作。

### 安全和使用
IDEA 未知有有效的攻击，强度在其设计时被认为是相对安全的。现代密码学中，算法如 AES 更为常见，但 IDEA 仍在某些领域和应用中使用。
IDEA 因涉及专利问题，在某些地方其使用受到限制，不过这些专利现已过期。
IDEA 算法的一个特点是设计简洁优雅、计算高效，但从安全的角度来看，稍显过时。对于大多数现代应用，AES 已成为首选算法。理解 IDEA 可以丰富对对称加密结构和设计的理解。

### python实现解密
参考https://github.com/Safecloudth/CVE-2024-53522/blob/main/CVE-2024-53522.ps1，全程依赖大模型进行转换，结果表明大模型可以用于编程语言转换。
```python
import struct  

class IDEA:  
    def __init__(self):  
        self.IV = None  
        self.CV = None  
        self.Key = None  
        self.EK = []  
        self.DK = []  

    def set_key(self, user_key):  
        self.Key = user_key  
        self.EK = []  
        self.DK = []  
        current_key = user_key  
        binary_string = ""  

        # CREATE EK  
        for i in range(7):  
            words = self.to_word(current_key)  

            self.EK.extend(words)  
            # Convert to long binary  
            for j in range(16):  
                binary_string += format(current_key[j], '08b')  
            # Circular Shift left 25  
            binary_string = binary_string[25:] + binary_string[:25]  
            current_key = from_binary_string(binary_string)  
            binary_string = ""  
        self.EK = self.EK[:52]  

        # CREATE DK  
        for i in range(8):  
            multiplier = i * 6  
            lower_index = 46 - multiplier  


            dk1 = self.mul_inv(self.EK[lower_index + 2], 65537)  
            self.DK.append(dk1)  

            tmp1 = 4  
            tmp2 = 3  
            if i == 0:  
                tmp1 = 3  
                tmp2 = 4  

            dk2 = self.sum_inv(self.EK[lower_index + tmp1], 65536)  
            self.DK.append(dk2)  

            dk3 = self.sum_inv(self.EK[lower_index + tmp2], 65536)  
            self.DK.append(dk3)  

            dk4 = self.mul_inv(self.EK[lower_index + 5], 65537)  
            self.DK.append(dk4)  

            self.DK.append(self.EK[lower_index])  
            self.DK.append(self.EK[lower_index + 1])  
            
        # 最后半轮  
        dk1 = self.mul_inv(self.EK[0], 65537)  
        self.DK.append(dk1)  

        dk2 = self.sum_inv(self.EK[1], 65536)  
        self.DK.append(dk2)  

        dk3 = self.sum_inv(self.EK[2], 65536)  
        self.DK.append(dk3)  

        dk4 = self.mul_inv(self.EK[3], 65537)  
        self.DK.append(dk4)  


    def set_iv(self, val):  
        self.IV = val  
        self.CV = self.IV  

    def reset(self):  
        self.CV = self.IV  

    def mod_mul(self, x, y):  
        return (x * y) % 65537   

    def mod_sum(self, x, y):  
        return (x + y) % 65536  

    def mul_inv(self, a, m):  
        m0 = m  
        y = 0  
        x = 1  
        if m == 1:  
            return 0  
        while a > 1:  
            q = a // m  
            t = m  
            m = a % m  
            a = t  
            t = y  
            y = x - q * y  
            x = t  
        if x < 0:  
            x = x + m0  
        return x  

    def sum_inv(self, x, m):  
        return m - x  

    def to_word(self, byte_array):  
        word_array = []  
        for i in range(0, len(byte_array), 2):  
            word = (byte_array[i] << 8) + byte_array[i+1]  
            word_array.append(word)  
        return word_array  

    def to_byte(self, word_array):  
        byte_array = bytearray()  
        for word in word_array:  
            byte_array.extend(struct.pack('>H', word))  
        return byte_array  

    def xor_block(self, x, y, size):  
        return bytes(a ^ b for a, b in zip(x[:size], y[:size]))  

    def decrypt_cbc(self, cipher):
        self.CV = self.IV
        size = len(cipher)
        plain = bytearray()

        i = 0
        if size >= 8:
            while i < size - 8:
                current_block = cipher[i:i+8]
                decrypted = self.decrypt_e_cb(current_block)
                xored = self.xor_block(decrypted, self.CV, 8)
                plain.extend(xored)
                self.CV = current_block
                i += 8

        if size % 8 != 0:
            self.CV = self.encrypt_e_cb(self.CV)
            remaining = cipher[i:]
            final_plain = self.xor_block(remaining, self.CV, len(remaining))
            plain.extend(final_plain)

        return bytes(plain)

    def encrypt_e_cb(self, plain):
        """ECB 模式加密"""
        X = self.to_word(plain)

        for i in range(8):
            multiplier = i * 6

            one = self.mod_mul(X[0], self.EK[multiplier + 0])
            two = self.mod_sum(X[1], self.EK[multiplier + 1])
            three = self.mod_sum(X[2], self.EK[multiplier + 2])
            four = self.mod_mul(X[3], self.EK[multiplier + 3])
            five = one ^ three
            six = two ^ four
            seven = self.mod_mul(five, self.EK[multiplier + 4])
            eight = self.mod_sum(six, seven)
            nine = self.mod_mul(eight, self.EK[multiplier + 5])
            ten = self.mod_sum(seven, nine)

            eleven = one ^ nine
            twelve = three ^ nine
            thirteen = two ^ ten
            fourteen = four ^ ten

            if i == 7:
                X = [eleven, thirteen, twelve, fourteen]
            else:
                X = [eleven, twelve, thirteen, fourteen]

        X[0] = self.mod_mul(X[0], self.EK[48])
        X[1] = self.mod_sum(X[1], self.EK[49])
        X[2] = self.mod_sum(X[2], self.EK[50])
        X[3] = self.mod_mul(X[3], self.EK[51])

        return self.to_byte(X)

    def decrypt_e_cb(self, cipher):
        """ECB 模式解密"""
        X = self.to_word(cipher)

        for i in range(8):
            multiplier = i * 6

            one = self.mod_mul(X[0], self.DK[multiplier + 0])
            two = self.mod_sum(X[1], self.DK[multiplier + 1])
            three = self.mod_sum(X[2], self.DK[multiplier + 2])
            four = self.mod_mul(X[3], self.DK[multiplier + 3])

            five = one ^ three
            six = two ^ four
            seven = self.mod_mul(five, self.DK[multiplier + 4])
            eight = self.mod_sum(six, seven)
            nine = self.mod_mul(eight, self.DK[multiplier + 5])
            ten = self.mod_sum(seven, nine)

            eleven = one ^ nine
            twelve = three ^ nine
            thirteen = two ^ ten
            fourteen = four ^ ten

            if i == 7:
                X = [eleven, thirteen, twelve, fourteen]
            else:
                X = [eleven, twelve, thirteen, fourteen]

        X[0] = self.mod_mul(X[0], self.DK[48])
        X[1] = self.mod_sum(X[1], self.DK[49])
        X[2] = self.mod_sum(X[2], self.DK[50])
        X[3] = self.mod_mul(X[3], self.DK[51])

        return self.to_byte(X)

def from_hex_string(hex_string):  
    return bytes.fromhex(hex_string)  

def from_binary_string(bin_string):  
    return bytes(int(bin_string[i:i+8], 2) for i in range(0, len(bin_string), 8))  

def decrypt(cipher="", key="", iv=""):  
    try:  
        idea = IDEA()  
        cipher = from_hex_string(cipher[64:])  
        idea.set_iv(from_hex_string(iv))  
        idea.set_key(from_hex_string(key))  
        decrypted = idea.decrypt_cbc(cipher)  
        print(f"decrypted: {decrypted}")  
    except Exception as e:  
        print(e)  

if __name__ == '__main__':  
    decrypt(cipher="EC7A1F8E20E0409B028BC4D003F9AAF9834C531862A5482B519D8D43B2D41D7730CC7E", key="E94596199382F62EFBA3CCD2946F5EF8", iv="B34392257D1E7BBE")
```