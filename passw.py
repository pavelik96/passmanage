from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA  # импорт генерации сертификатов


def gen_cert():  # генерация сертификатов
    key = RSA.generate(2048)  # 2048 - длина ключа в битах
    open('private.pem', 'wb').write(key.export_key('PEM'))  # приватный ключ
    open('public.pem', 'wb').write(key.publickey().export_key('PEM'))  # публичный ключ
    return


def encode_key(mess):  # кодировка сообщения
    key2 = RSA.import_key(open('public.pem').read())
    cipher_rsa = PKCS1_OAEP.new(key2)
    cryp_message = cipher_rsa.encrypt(mess)
    return cryp_message  # возвращаем nonce, зашифрованный текст и тег


def decode_key(ciphertext_from_out):  # Для расшифровки сообщения
    key3 = RSA.import_key(open('private.pem').read())
    cipher = PKCS1_OAEP.new(key3)
    plaintext = cipher.decrypt(ciphertext_from_out)
    return plaintext


# генерируем сертификаты и получаем ключ
gen_cert()
print(open('private.pem').read())
print(open('public.pem').read())

# шифруем строку

login = input('логин')  # только на английском
password1 = input('пароль')  # только на английском

dub1 = login + ',' + password1

# dub1 = "password"  # строка для шифрования (нужны именно двойные ковычки)
dub = dub1.encode('utf_8')
ciphertext = encode_key(dub)
print(ciphertext)
ciphertext_dec = decode_key(ciphertext)
print(ciphertext_dec)
# расшифровываем строку
