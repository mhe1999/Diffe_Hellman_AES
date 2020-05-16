import socket
import re

#server generate a prime number and generater(for example with openssl)
prime = 0xba01af369bef860023562c7f5e517a9b
g = 2
server_private = 0x4de0438f4457df470dd099a3c108a9cc
server_public = (g ^ server_private) % prime

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        print('sending the public paramters of Diffie-hellman to client...\n\n')
        data = 'INITIAL_PARAMS = prime:' + str(prime) + ', g:' + str(g)
        conn.sendall(data.encode())
        print('sending the sever public key to client...\n\n')
        data = 'SERVER_PUBLIC_KEY =' + str(server_public)
        conn.sendall(data.encode())
        while True:
            data = conn.recv(1024)
            if not data:
                continue
            data = data.decode()
            if data.startswith('CLIENT_PUBLIC_KEY'):
                client_public = int(re.findall('[0-9]+' , data)[0])
                print('client public key:' , hex(client_public))
                session_key = (client_public ^ server_private) % prime
                print("session_key:" , hex(session_key))
