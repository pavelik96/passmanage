#import tkinter as Tk
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import sqlite3
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA  # импорт генерации сертификатов


# import pass
# from tkinter import messagebox

def encode_key(mess, pub_key):  # кодировка сообщения
    key2 = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(key2)
    cryp_message = cipher_rsa.encrypt(mess)
    return cryp_message  # возвращаем nonce, зашифрованный текст и тег


def path():
    public_key_path['text'] = filedialog.askopenfile().name


def path_private():
    private_lb['text'] = filedialog.askopenfile().name


def path_bd():
    work_bdl['text'] = filedialog.askopenfile().name


def gen_cert():  # генерация сертификатов
    key = RSA.generate(4096)  # 2048 - длина ключа в битах
    open('private.pem', 'wb').write(key.export_key('PEM'))  # приватный ключ
    open('public.pem', 'wb').write(key.publickey().export_key('PEM'))  # публичный ключ
    return


def ins_bd():
    conn_in = sqlite3.connect(work_bdl['text'])  # Присоединение к БД в функции
    cur_in = conn_in.cursor()  # Создаем курсор для выполнения запросов
    # Создаем таблицу если не было
    cur_in.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, login TEXT, password BYTES)')
    login_in = login_entry.get()
    password_non_crypt = pass_entry.get()
    password1 = password_non_crypt.encode('utf-8')
    password = encode_key(password1, open(public_key_path['text']).read())
    # Добавляем запись в таблицу преобразуя пароль в байтовую строку
    cur_in.execute('INSERT INTO users (login, password) VALUES (?, ?)',
                   (login_in, password))  # Добавляем запись в таблицу
    conn_in.commit()


def decode_key(ciphertext_from_out):  # Для расшифровки сообщения
    key_encode = open(private_lb['text']).read()
#    key3 = RSA.import_key(key_encode.encode('utf-8'))
    key3 = RSA.import_key(key_encode)
    cipher = PKCS1_OAEP.new(key3)
    plaintext = cipher.decrypt(ciphertext_from_out)
    return plaintext


def outer_bd():
    conn_inOut = sqlite3.connect(work_bdl['text'])  # Присоединение к БД в функции
    cur_out = conn_inOut.cursor()  # Создаем курсор для выполнения запросов
    login_out = login_entry_out.get()
    # Выбираем записи из таблицы, сука, блядская запятая в кортеже, она должна быть всегда (login_out,)
    cur_out.execute('SELECT * FROM users where login=?', (login_out,))
    rows = cur_out.fetchall()
    for row in rows:  # Выводим результат
        password = decode_key(row[2])
        output = (row[1], password)
        pass_out.insert(0, output)


#   for row in rows:  # Выводим результат
#       password = decode_key(row[2])
#       print(row[0], row[1], password.decode())
#   outer = input('получить ещё пароль? Y или N')


window = Tk()  # Создаём окно приложения.
window.title("Pass-manage")  # Добавляем название приложения.
window.geometry('350x300')  # задание размера
window.option_add("*tearOff", False)
frame = Frame(
    window,  # Обязательный параметр, который указывает окно для размещения Frame.
    padx=10,  # Задаём отступ по горизонтали.
    pady=10  # Задаём отступ по вертикали.
)

frame.pack(expand=True)
# Не забываем позиционировать виджет в окне. Здесь используется метод pack. С помощью свойства
# expand=True указываем, что Frame заполняет весь контейнер, созданный для него.

work_bdl = Label(
    frame,
    text="База данных"
)
work_bdl.grid(row=1, column=1)

work_bdl_bt = Button(
    frame,
    text='База паролей',
    command=path_bd
)
work_bdl_bt.grid(row=1, column=2)

public_key_path = Label(  # отображение пути к public key
    frame,
    text="publickey"
)
public_key_path.grid(row=2, column=1)  # позиционирование описания пути к private key

public_btn = Button(  # кнопка выбора приватного ключа
    frame,
    text='publickey',
    command=path  # Позволяет запустить событие с функцией при нажатии на кнопку.
)
public_btn.grid(row=2, column=2)  # позиционирование кнопки выбора приватного ключа

login_lb = Label(
    frame,
    text='login'
)
login_lb.grid(row=3, column=1)

login_entry = Entry(  # ввод логина
    frame
)
login_entry.insert(0, '')  # базовый текст
login_entry.grid(row=4, column=1)

pass_lb = Label(
    frame,
    text='password'
)
pass_lb.grid(row=3, column=2)

pass_entry = Entry(  # ввод пароля
    frame,
)
pass_entry.insert(0, '')  # базовый текст
pass_entry.grid(row=4, column=2)

ins_bd = Button(
    frame,
    text='Добавить в базу',
    command=ins_bd
)
ins_bd.grid(row=5, column=2)

menu_fail = Menu()
file = Menu()

file.add_command(label='GenSert', command=gen_cert)
menu_fail.add_cascade(label='File', menu=file)

window.config(menu=menu_fail)

login_lb_out = Label(
    frame,
    text='login'
)
login_lb_out.grid(row=6, column=1)

login_entry_out = Entry(  # ввод логина
    frame
)
login_entry_out.insert(0, '')  # базовый текст
login_entry_out.grid(row=7, column=1)

private_btn = Button(  # кнопка выбора приватного ключа
    frame,
    text='privatekey',
    command=path_private  # Позволяет запустить событие с функцией при нажатии на кнопку.
)
private_btn.grid(row=6, column=2)  # позиционирование кнопки выбора приватного ключа
private_lb = Label(frame, text='')  # для хранения private
private_lb.grid(row=8, column=1)

login_bt_out = Button(
    frame,
    text='Получить пароль',
    command=outer_bd
)
login_bt_out.grid(row=7, column=2)

pass_out = Entry(frame)
pass_out.grid(row=9, column=1)

window.mainloop()  # что бы окно не закрывалось
