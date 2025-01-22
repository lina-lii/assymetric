import socket
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Константы для протокола Диффи-Хеллмана
P = 23  # Простое число (для демонстрации можно взять небольшое значение)
G = 5   # Генератор

def diffie_hellman_generate_secret(my_private, peer_public, p):
    """Функция для вычисления общего секрета."""
    return pow(peer_public, my_private, p)

def encrypt_message(message, key):
    """Шифрование сообщения с использованием AES-256 в режиме CBC."""
    iv = os.urandom(16)  # Генерация случайного вектора инициализации
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # Добавление простого дополнения (padding), чтобы длина сообщения была кратной 16
    padded_message = message + b" " * (16 - len(message) % 16)
    return iv + encryptor.update(padded_message) + encryptor.finalize()

def decrypt_message(ciphertext, key):
    """Расшифровка сообщения с использованием AES-256 в режиме CBC."""
    iv, ct = ciphertext[:16], ciphertext[16:]  # Разделение на IV и зашифрованные данные
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ct) + decryptor.finalize()
    return decrypted_padded_message.rstrip(b" ")  # Удаление дополнения

def server():
    # Создание и настройка серверного сокета
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 65432))  # Привязка к локальному хосту и порту
    server_socket.listen(1)
    print("Сервер ожидает подключения...")

    # Ожидание подключения клиента
    conn, addr = server_socket.accept()
    print(f"Подключение установлено с {addr}")

    # Генерация приватного и публичного ключей для протокола Диффи-Хеллмана
    private_key = secrets.randbelow(P)
    public_key = pow(G, private_key, P)

    # Получение публичного ключа клиента
    client_public_key = int(conn.recv(1024).decode())
    print(f"Получен публичный ключ клиента: {client_public_key}")

    # Отправка публичного ключа сервера клиенту
    conn.sendall(str(public_key).encode())
    print(f"Отправлен публичный ключ сервера: {public_key}")

    # Вычисление общего секрета
    shared_secret = diffie_hellman_generate_secret(private_key, client_public_key, P)
    print(f"Общий секрет: {shared_secret}")

    # Преобразование общего секрета в симметричный ключ (16 байт)
    symmetric_key = shared_secret.to_bytes(16, "big")

    # Получение зашифрованного сообщения от клиента
    encrypted_message = conn.recv(1024)
    print(f"Получено зашифрованное сообщение: {encrypted_message}")

    # Расшифровка сообщения
    decrypted_message = decrypt_message(encrypted_message, symmetric_key)
    print(f"Расшифрованное сообщение: {decrypted_message.decode()}")

    # Отправка ответа клиенту
    response = b"Привет, клиент!"
    encrypted_response = encrypt_message(response, symmetric_key)
    conn.sendall(encrypted_response)
    print("Отправлен зашифрованный ответ клиенту.")

    # Закрытие соединения
    conn.close()
    server_socket.close()
