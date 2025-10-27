#подключение библиотек
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#определение размера ключа
BLOCK_SIZE = 32 # Bytes
# Генерация случайного ключа (32 байт = 256 бит)
key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_ECB)

massage = b'hello'

padded = pad(massage, BLOCK_SIZE)

# Шифруем
msg = cipher.encrypt(padded)
print(msg.hex())

# Расшифровка
decipher = AES.new(key, AES.MODE_ECB)
msg_dec = decipher.decrypt(msg)
print(unpad(msg_dec, BLOCK_SIZE))