import socket
from threading import Thread

Host = "10.1.40.74"
Port = 6390
clients = []

def handle_client(client_socket):
    while True:
        try:
            msg = client_socket.recv(8192)
            if not msg: break
            # On renvoie le message à tous les AUTRES clients
            for c in clients:
                if c != client_socket:
                    c.send(msg)
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
    Thread(target=handle_client, args=[client], daemon=True).start()

# Le thread principal reste en vie pour maintenir le serveur
try:
    while True: pass
except KeyboardInterrupt:
    serveur.close()