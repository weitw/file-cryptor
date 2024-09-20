# -*- coding=utf-8 -*-
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib


class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()  # 使用 SHA-256 对 AES 密钥进行处理

    def encrypt(self, raw):
        raw = pad(raw.encode(), AES.block_size)
        iv = os.urandom(AES.block_size)  # 生成随机 IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')
        return encrypted

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size).decode('utf-8')
        return decrypted


if __name__ == '__main__':
    key = "wtw0913*#"
    aes = AESCipher(key)
    result = aes.encrypt("在 FileEncryptor 类中添加对 key.json 文件加解密的处理。")
    print(aes.encrypt(result))
    print(aes.decrypt(result))