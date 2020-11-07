from Crypto.Cipher import AES
import socket

HOST = '127.0.0.1'
PORT = 65433

prime_key = b'crypto = awesome'
IV = b'security = swell'

mode = ''
key = b''


def receive_cbc_blocks(sock, blocks):
    content = b''
    xor_term = IV

    # receive encrypted blocks one at a time, except last one
    for cycle in range(blocks):
        cipher_block = sock.recv(16)

        term_copy = []
        term_copy[:] = cipher_block
        cipher_block = AES.new(key, AES.MODE_ECB).decrypt(cipher_block)
        xor_result = bytes(a ^ b for a, b in zip(cipher_block, xor_term))
        xor_term = term_copy

        content += xor_result

    return content, xor_term


def receive_last_cbc_block(sock, content, xor_term):
    # for last one, get padding size
    padding = sock.recv(2)
    padding = int.from_bytes(padding, 'big')
    print('Receiving necessary padding for last block:', padding)

    # decrypt last block
    cipher_block = sock.recv(16)
    cipher_block = AES.new(key, AES.MODE_ECB).decrypt(cipher_block)
    xor_result = bytes(a ^ b for a, b in zip(cipher_block, xor_term))

    # get rid of padding
    xor_result = xor_result[:-padding]
    content += xor_result

    return content


def receive_cfb_blocks(sock, blocks):
    content = b''
    xor_term = IV

    for cycle in range(blocks):
        cipher_block = sock.recv(16)

        xor_term = AES.new(key, AES.MODE_ECB).encrypt(xor_term)
        xor_result = bytes(a ^ b for a, b in zip(cipher_block, xor_term))
        xor_term = cipher_block

        content += xor_result

    return content, xor_term


def receive_last_cfb_block(sock, content, xor_term):
    padding = sock.recv(2)
    padding = int.from_bytes(padding, 'big')
    print('Receiving necessary padding for last block:', padding)

    cipher_block = sock.recv(16)
    xor_term = AES.new(key, AES.MODE_ECB).encrypt(xor_term)
    xor_result = bytes(a ^ b for a, b in zip(cipher_block, xor_term))

    xor_result = xor_result[:-padding]
    content += xor_result

    return content


def receive_encrypted_file(sock):
    blocks = sock.recv(2)
    blocks = int.from_bytes(blocks, byteorder='big')
    print('Receiving number of blocks:', blocks)

    if mode == b'CBC':
        content, xor_term = receive_cbc_blocks(sock, blocks)
        content = receive_last_cbc_block(sock, content, xor_term)
        fd = open('b/tema_cbc.pdf', 'wb')
        fd.write(content)
    elif mode == b'CFB':
        content, xor_term = receive_cfb_blocks(sock, blocks)
        content = receive_last_cfb_block(sock, content, xor_term)
        fd = open('b/tema_cfb.pdf', 'wb')
        fd.write(content)

    print('File received!')


def decrypt_key(enc_key):
    return AES.new(prime_key, AES.MODE_CBC, IV).decrypt(enc_key)


def establish_comm_info():
    global mode
    global key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print('Connected to A!')
        mode = s.recv(3)  # CBC or CFB
        print('Received mode:', mode)
        key = s.recv(16)
        print('Received encrypted key:', key)
        key = decrypt_key(key)
        print('Decrypted key:', key)
        s.sendall(b'1')
        receive_encrypted_file(s)
    s.close()


if __name__ == '__main__':
    establish_comm_info()
