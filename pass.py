from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA  # импорт генерации сертификатов
import sqlite3


def gen_cert():  # генерация сертификатов
    key = RSA.generate(4096)  # 2048 - длина ключа в битах
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


def ins_bd():
    name_bd = input("Введите название для базы паролей(только латиница)")
    conn_in = sqlite3.connect(name_bd + '.db')  # Присоединение к БД в функции
    cur_in = conn_in.cursor()  # Создаем курсор для выполнения запросов
    # Создаем таблицу если не было
    cur_in.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, login TEXT, password BYTES)')
    ans = input('Добавить пользователя? Y or N\n')
    if ans == 'y' or ans == 'Y':
        while (ans == 'y') or (ans == 'Y'):
            login_in = input('логин: \n')
            password_non_crypt = input('пароль : \n')
            password1 = password_non_crypt.encode('utf-8')
            password = encode_key(password1)
            # Добавляем запись в таблицу преобразуя пароль в байтовую строку
            cur_in.execute('INSERT INTO users (login, password) VALUES (?, ?)',
                           (login_in, password))  # Добавляем запись в таблицу
            ans = input('Добавить ещё пароль? \n')
    conn_in.commit()


def outer_bd():
    name_bdOut = input("Введите название базы паролей(только латиница)")
    conn_inOut = sqlite3.connect(name_bdOut + '.db')  # Присоединение к БД в функции
    cur_out = conn_inOut.cursor()  # Создаем курсор для выполнения запросов
    login_out = input('Введите логин для которого нужно вывести пароль')
    # Выбираем записи из таблицы, сука, блядская запятая в кортеже, она должна быть всегда
    cur_out.execute('SELECT * FROM users where login=?', (login_out,))
    rows = cur_out.fetchall()
    for row in rows:  # Выводим результат
        password = decode_key(row[2])
        print(row[0], row[1], password.decode())


# gen_cert()
# ins_bd()
outer_bd()
# conn = sqlite3.connect('example.db')  # Присоедине123ние к БД

# cur = conn.cursor()  # Создаем курсор для выполнения запросов

# cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)')  # Создаем таблицу

# cur.execute('INSERT INTO users (name, age) VALUES (?, ?)', ('John', 30))  # Добавляем запись в таблицу

# conn.commit()  # Сохраняем изменения

# cur.execute('SELECT * FROM users')  # Выбираем записи из таблицы
# rows = cur.fetchall()

# for row in rows:  # Выводим результат
#    print(row)

# генерируем сертификаты и получаем ключ
'''gen_cert()
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
'''
