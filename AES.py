from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Генерация случайного ключа (16 байт = 128 бит)
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)

# Сообщение для шифрования
data = b"Secret message"

# Данные должны быть кратны 16 байтам, добавляем padding
padded = pad(data, AES.block_size)

# Шифруем
encrypted = cipher.encrypt(padded)
print("Зашифрованное сообщение:", encrypted)

# Для расшифровки нужен IV (инициализационный вектор)
iv = cipher.iv
cipher_dec = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(cipher_dec.decrypt(encrypted), AES.block_size)
print("Расшифрованное сообщение:", decrypted.decode())