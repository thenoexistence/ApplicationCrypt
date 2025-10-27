from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes 

# Глобальные переменные для хранения ключей (для демонстрации)
aes_ecb_key = None
aes_cbc_key = None
aes_cbc_iv = None
rsa_private_key = None

def aes_ebc_encrypt(message):
    global aes_ecb_key
    BLOCK_SIZE = 32
    aes_ecb_key = get_random_bytes(32)  # Сохраняем ключ для дешифровки
    cipher = AES.new(aes_ecb_key, AES.MODE_ECB)
    padded = pad(message, BLOCK_SIZE)
    encrypted = cipher.encrypt(padded)
    print("Зашифрованное сообщение (hex):", encrypted.hex())
    return encrypted

def aes_ebc_decrypt(encrypted_message):
    global aes_ecb_key
    if aes_ecb_key is None:
        print("Ошибка: нет зашифрованных данных или ключа")
        return
    
    decipher = AES.new(aes_ecb_key, AES.MODE_ECB)
    decrypted = decipher.decrypt(encrypted_message)
    unpadded = unpad(decrypted, 32)
    print("Расшифрованное сообщение:", unpadded.decode())
    return unpadded

def aes_cbc_encrypt(message):
    global aes_cbc_key, aes_cbc_iv
    aes_cbc_key = get_random_bytes(16)
    cipher = AES.new(aes_cbc_key, AES.MODE_CBC)
    aes_cbc_iv = cipher.iv  # Сохраняем IV для дешифровки
    
    padded = pad(message, AES.block_size)
    encrypted = cipher.encrypt(padded)
    print("Зашифрованное сообщение:", encrypted.hex())
    return encrypted

def aes_cbc_decrypt(encrypted_message):
    global aes_cbc_key, aes_cbc_iv
    if aes_cbc_key is None or aes_cbc_iv is None:
        print("Ошибка: нет зашифрованных данных или ключа/IV")
        return
    
    cipher = AES.new(aes_cbc_key, AES.MODE_CBC, aes_cbc_iv)
    decrypted = cipher.decrypt(encrypted_message)
    unpadded = unpad(decrypted, AES.block_size)
    print("Расшифрованное сообщение:", unpadded.decode())
    return unpadded

def _rsa_encrypt(message):
    global rsa_private_key
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )  
    public_key = rsa_private_key.public_key()

    encrypted_message = public_key.encrypt(
        message, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Зашифрованное сообщение:", encrypted_message.hex())
    return encrypted_message

def _rsa_decrypt(encrypted_message):
    global rsa_private_key
    if rsa_private_key is None:
        print("Ошибка: нет зашифрованных данных или приватного ключа")
        return
    
    decrypted_message = rsa_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Расшифрованное сообщение:", decrypted_message.decode())
    return decrypted_message

# Переменные для хранения зашифрованных данных
encrypted_data = None

print("Добро пожаловать! Приложение по шифрованию готова к работе")

while True:  # Исправлено условие цикла
    choice = input("\nВыберите режим приложения:\n" \
                   "1. Шифрование\n" \
                   "2. Расшифровка\n" \
                   "3. Выход\n" \
                   "Ваш выбор: ")
    
    if choice == "1":
        usertext = input("Введите ваш текст: ")
        message = usertext.encode("UTF-8")
        
        print("Выберите метод шифрования:\n" \
              "1. AES ECB\n" \
              "2. AES CBC\n" \
              "3. RSA")
        crypt_choice = input("Ваш выбор: ")
        
        match crypt_choice:
            case "1": 
                encrypted_data = aes_ebc_encrypt(message)
            case "2": 
                encrypted_data = aes_cbc_encrypt(message)
            case "3": 
                encrypted_data = _rsa_encrypt(message)
            case _: 
                print("Неверный выбор метода шифрования")
                continue
                
    elif choice == "2":
        if encrypted_data is None:
            print("Сначала выполните шифрование!")
            continue
            
        print("Выберите метод дешифровки:\n" \
              "1. AES ECB\n" \
              "2. AES CBC\n" \
              "3. RSA")
        crypt_choice = input("Ваш выбор: ")
        
        match crypt_choice:
            case "1": 
                aes_ebc_decrypt(encrypted_data)
            case "2": 
                aes_cbc_decrypt(encrypted_data)
            case "3": 
                _rsa_decrypt(encrypted_data)
            case _: 
                print("Неверный выбор метода дешифровки")
                
    elif choice == "3":
        print("Спасибо за использование программы шифрования!")
        break
    else:
        print("Неверный выбор. Попробуйте снова.")