from Crypto.Cipher import AES
import os
import socket

HOST = '127.0.0.1'
PORT = 65432

cbc_key = os.urandom(16)
cfb_key = os.urandom(16)

prime_key = b'crypto = awesome'
IV = b'security = swell'


def share_comm_info():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print('Waiting on A...')
        s.listen()
        conn, addr = s.accept()

        print('Connected to A at', addr)
        while True:
            mode = conn.recv(1024)
            if not mode:
                break
            if mode == b'CBC':
                print('Sent CBC key ', cbc_key, 'encrypted as', encrypt_key(cbc_key))
                conn.send(encrypt_key(cbc_key))
            elif mode == b'CFB':
                print('Sent CFB key ', cfb_key, 'encrypted as', encrypt_key(cfb_key))
                conn.send(encrypt_key(cfb_key))

    conn.close()
    s.close()


def encrypt_key(key):
    return AES.new(prime_key, AES.MODE_CBC, IV).encrypt(key)


def decrypt_key(enc_key):
    return AES.new(prime_key, AES.MODE_CBC, IV).decrypt(enc_key)


if __name__ == '__main__':
    share_comm_info()
