import socket
import re

cilent_private = 0x7250f5b473a13f2faffa851c4076bc2c



HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        data = s.recv(1024)
        if not data:
            continue
        data = data.decode()
        print('Received -------> "', data, '"')

        if data.startswith('INITIAL_PARAMS'):
            prime = int(re.findall('prime:([0-9]+),', data)[0])
            g = int(re.findall('g:([0-9]+)', data)[0])
            print('prime:' , hex(prime))
            print('g:' , hex(g))
            client_public = (g ^ cilent_private) % prime
            data = 'CLIENT_PUBLIC_KEY =' + str(client_public)
            print('sending the client public key to server...')
            s.sendall(data.encode())

        if data.startswith('SERVER_PUBLIC_KEY'):
            server_public = int(re.findall('[0-9]+' , data)[0])
            print('server public key:' , hex(server_public))
            session_key = (server_public ^ cilent_private) % prime
            print("session_key:" , hex(session_key))
