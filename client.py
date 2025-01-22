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

def client():
    # Создание и настройка клиентского сокета
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 65432))

    # Генерация приватного и публичного ключей для протокола Диффи-Хеллмана
    private_key = secrets.randbelow(P)
    public_key = pow(G, private_key, P)

    # Отправка публичного ключа клиента серверу
    client_socket.sendall(str(public_key).encode())
    print(f"Отправлен публичный ключ клиента: {public_key}")

    # Получение публичного ключа сервера
    server_public_key = int(client_socket.recv(1024).decode())
    print(f"Получен публичный ключ сервера: {server_public_key}")

    # Вычисление общего секрета
    shared_secret = diffie_hellman_generate_secret(private_key, server_public_key, P)
    print(f"Общий секрет: {shared_secret}")

    # Преобразование общего секрета в симметричный ключ (16 байт)
    symmetric_key = shared_secret.to_bytes(16, "big")

    # Отправка зашифрованного сообщения серверу
    message = b"Привет, сервер!"
    encrypted_message = encrypt_message(message, symmetric_key)
    client_socket.sendall(encrypted_message)
    print("Отправлено зашифрованное сообщение серверу.")

    # Получение зашифрованного ответа от сервера
    encrypted_response = client_socket.recv(1024)
    print(f"Получен зашифрованный ответ: {encrypted_response}")

    # Расшифровка ответа
    decrypted_response = decrypt_message(encrypted_response, symmetric_key)
    print(f"Расшифрованный ответ: {decrypted_response.decode()}")

    # Закрытие соединения
    client_socket.close()
