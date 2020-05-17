import socket
import re
import base64
from Crypto.Cipher import AES

def base64_encode(message_bytes):
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def base64_decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes

def encryption(session_key, plaintext):
    cipher = AES.new(session_key.to_bytes(16, byteorder = 'big'),AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode()) # encryte data
    return ciphertext, nonce

def decryption(session_key, message_bytes, nonce):
    cipher = AES.new(session_key.to_bytes(16, byteorder = 'big'), AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(message_bytes)               # decrype message with session key and nonce
    plaintext = plaintext.decode()
    return plaintext

# server generate a prime number and generater(for example with openssl)
prime = 0xba01af369bef860023562c7f5e517a9b
g = 2

server_private = 0x4de0438f4457df470dd099a3c108a9cc # server private key
server_public = (g ^ server_private) % prime    # calculate public key

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        print('\nsending the public paramters of Diffie-hellman to client...\n')
        data = 'INITIAL_PARAMS = prime:' + str(prime) + ', g:' + str(g) # send two public paramets(prime number and generator) without encryption
        conn.sendall(data.encode())

        print("sending the server's public key to client...\n")          # send server's public key without encryption
        data = 'SERVER_PUBLIC_KEY =' + str(server_public)
        conn.sendall(data.encode())

        while True:
            data = conn.recv(1024)
            if not data:
                continue
            data = data.decode()
            if data.startswith('CLIENT_PUBLIC_KEY'):                    # Receiving client public key
                print('Received -------> "', data, '"')
                client_public = int(re.findall('[0-9]+' , data)[0])
                print('server public key:' , hex(server_public))
                print('server private key:' , hex(server_private))
                print('client public key:' , hex(client_public))

                session_key = (client_public ^ server_private) % prime  # calculate session key base on client public key and server private key
                print("session_key:" , hex(session_key), '\n\n')

            if data.startswith('CIPHER_TEXT'):                          # Receiving client cipherText which encryted with session key
                print('Received -------> "', data, '"')
                ciphertext = re.findall('CIPHER_TEXT:(.+),', data)[0]
                nonce = re.findall('NONCE:(.+)', data)[0]
                print('raw cipher text of Received message: ', ciphertext)

                message_bytes = base64_decode(ciphertext)
                message_bytes_nonce = base64_decode(nonce)              # convert bsae64 nonce and cipherText to bytes
                plaintext = decryption(session_key, message_bytes, message_bytes_nonce)
                print('the dectypted message of Received message: ', plaintext)

                plaintext = input('\nEnter your text to send\n')
                ciphertext, nonce = encryption(session_key, plaintext)

                base64_message = base64_encode(ciphertext)
                base64_message_nonce = base64_encode(nonce)
                print('\nthe plain text is  :', plaintext)
                print('the cipher text is :', base64_message)
                print('sending \'', base64_message, '\' (cipher text) to client...\n')

                data = 'CIPHER_TEXT :' + str(base64_message) + ', NONCE:' + str(base64_message_nonce) # send encryted data to client
                conn.sendall(data.encode())
                break
