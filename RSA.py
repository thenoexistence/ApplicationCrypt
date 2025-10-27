from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives import serialization 

from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes 

# Генерация ключевой пары (открытого и закрытого ключа)  
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  
public_key = private_key.public_key() 

# Сообщение для шифрования  
message = b"This is security message"  
# Шифрование сообщения  
mgf=padding.MGF1(algorithm=hashes.SHA256())
encrypted_message = public_key.encrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

print("Зашифрованное сообщение:", encrypted_message)  

# Дешифрование
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Расшифрованное сообщение:", decrypted_message.decode())