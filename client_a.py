from Crypto.Cipher import AES
import socket

HOST = '127.0.0.1'
PORT = 65432  # port used by the server and A
PORT_B = 65433  # port used by A and B

prime_key = b'crypto = awesome'
IV = b'security = swell'

mode = ''
key = b''


def send_cbc_blocks(conn, content, blocks):
    xor_term = IV

    # encrypt blocks up until the last, incomplete one, and send them to B
    for cycle in range(blocks):
        current_block = content[:16]
        content = content[16:]

        xor_result = bytes(a ^ b for a, b in zip(current_block, xor_term))
        cipher_block = AES.new(key, AES.MODE_ECB).encrypt(xor_result)
        xor_term = cipher_block

        conn.send(cipher_block)

    return content, xor_term


def send_last_cbc_block(conn, content, xor_term):
    # encrypt and send the last block, after padding
    content = bytearray(content)

    padding = 16 - len(content)
    print('Sending necessary padding for last block:', padding)
    conn.send(padding.to_bytes(2, 'big'))

    for pad in range(padding):
        content.append(0)

    xor_result = bytes(a ^ b for a, b in zip(content, xor_term))
    cipher_block = AES.new(key, AES.MODE_ECB).encrypt(xor_result)
    conn.send(cipher_block)


def send_cfb_blocks(conn, content, blocks):
    cipher_block = IV

    for cycle in range(blocks):
        current_block = content[:16]
        content = content[16:]

        cipher_block = AES.new(key, AES.MODE_ECB).encrypt(cipher_block)
        xor_result = bytes(a ^ b for a, b in zip(current_block, cipher_block))
        cipher_block = xor_result

        conn.send(xor_result)

    return content, cipher_block


def send_last_cfb_block(conn, content, cipher_block):
    content = bytearray(content)

    padding = 16 - len(content)
    print('Sending necessary padding for last block:', padding)
    conn.send(padding.to_bytes(2, 'big'))

    for pad in range(padding):
        content.append(0)

    cipher_block = AES.new(key, AES.MODE_ECB).encrypt(cipher_block)
    xor_result = bytes(a ^ b for a, b in zip(content, cipher_block))
    conn.send(xor_result)


def send_encrypted_file(conn):
    fd = open('a/tema.pdf', 'rb')
    content = fd.read()

    blocks = int(len(content) / 16)  # this does not account for leftover
    print('Sending number of blocks:', blocks)
    conn.send(blocks.to_bytes(2, 'big'))

    if mode == 'CBC':
        content, xor_term = send_cbc_blocks(conn, content, blocks)
        send_last_cbc_block(conn, content, xor_term)
    elif mode == 'CFB':
        content, cipher_block = send_cfb_blocks(conn, content, blocks)
        send_last_cfb_block(conn, content, cipher_block)

    print('File sent!')


def decrypt_key(enc_key):
    return AES.new(prime_key, AES.MODE_CBC, IV).decrypt(enc_key)


def get_comm_info():
    global mode
    global key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print('Connected to KM!')
        mode = str(input('Enter operation mode, CBC or CFB: '))
        s.send(mode.encode())
        key = s.recv(16)
    print('Received encrypted key:', key)
    print('Decrypted key:', decrypt_key(key))


def share_comm_info():
    global key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_B))
        print('Waiting on B...')
        s.listen()
        conn, addr = s.accept()

    print('Connected to B at', addr)
    conn.send(mode.encode())
    conn.send(key)
    key = decrypt_key(key)
    okay = conn.recv(1)

    if okay == b'1':
        send_encrypted_file(conn)

    conn.close()
    s.close()


if __name__ == '__main__':
    get_comm_info()
    share_comm_info()
