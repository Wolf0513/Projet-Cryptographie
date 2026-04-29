import socket
from threading import Thread
import time

Host = "10.1.40.74"
Port = 6390
clients = []

def handle_client(client_socket):
    while True:
        try:
            msg = client_socket.recv(8192)
            if msg:
                for c in clients:
                    if c != client_socket:
                        c.send(msg)
            else:
                break
        except:
            break
    if client_socket in clients: clients.remove(client_socket)
    client_socket.close()

serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serveur.bind((Host, Port))
serveur.listen(2)

print("Serveur Relais en attente de 2 clients...")

while len(clients) < 2:
    client, addr = serveur.accept()
    clients.append(client)
    print(f"Client {len(clients)} connecté.")

print("Les deux clients sont connectés. Activation du relais...")
for c in clients:
    Thread(target=handle_client, args=[c], daemon=True).start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    serveur.close()