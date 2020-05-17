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

cilent_private = 0x7250f5b473a13f2faffa851c4076bc2c # client private key

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        data = s.recv(1024)
        if not data:
            continue
        data = data.decode()
        print('Received -------> "', data, '"')

        if data.startswith('INITIAL_PARAMS'):                   # Receiving initial parameters
            prime = int(re.findall('prime:([0-9]+),', data)[0])
            g = int(re.findall('g:([0-9]+)', data)[0])

            print('prime:' , hex(prime))
            print('g:' , hex(g))

            client_public = (g ^ cilent_private) % prime        # calculate public key
            data = 'CLIENT_PUBLIC_KEY =' + str(client_public)
            print("\nsending the client's public key to server...\n") # send client's public key without encryption
            s.sendall(data.encode())

        if data.startswith('SERVER_PUBLIC_KEY'):                # Receiving servers's public key
            server_public = int(re.findall('[0-9]+' , data)[0])
            print('client public key:' , hex(client_public))
            print('client private key:', hex(cilent_private))
            print('server public key:' , hex(server_public))
            session_key = (server_public ^ cilent_private) % prime  # calculate session key base on server's public key and client's private key
            print("session_key:" , hex(session_key), '\n')

            plaintext = input('Enter your text to send\n')
            ciphertext, nonce = encryption(session_key, plaintext)

            base64_message = base64_encode(ciphertext)
            base64_message_nonce = base64_encode(nonce)
            print('\nthe plain text is  :', plaintext)
            print('the cipher text is :', base64_message)
            print('sending \'', base64_message, '\' (cipher text) to server...\n')
            data = 'CIPHER_TEXT:' + str(base64_message) + ', NONCE:' + str(base64_message_nonce) # send encryted data to server
            s.sendall(data.encode())

        if data.startswith('CIPHER_TEXT :'):                          # Receiving server's cipherText which encryted with session key
            print('Received -------> "', data, '"')
            ciphertext = re.findall('CIPHER_TEXT :(.+),', data)[0]
            nonce = re.findall('NONCE:(.+)', data)[0]
            print('\nraw cipher text of Received message: ', ciphertext)

            message_bytes = base64_decode(ciphertext)
            message_bytes_nonce = base64_decode(nonce)              # convert bsae64 nonce and cipherText to bytes
            plaintext = decryption(session_key, message_bytes, message_bytes_nonce)
            print('the dectypted message of Received message: ', plaintext)
            break
