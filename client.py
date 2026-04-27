import socket
from threading import Thread
import json
from crypto import dechiffrement
from interface import lancer_interface, afficher_message
import hashlib

Host = "10.1.40.74"
Port = 6390

def receive(client_socket):
    while True:
        try:
            requete = client_socket.recv(8192)
            if not requete:
                print("Connexion perdue")
                break
            paquet = json.loads(requete.decode('utf-8'))
            message_dechiffre = dechiffrement(paquet['ch2'], paquet['key1'], paquet['key2'])
            afficher_message(message_dechiffre)
        except Exception as e:
            print(f"Erreur de réception : {e}")
            break

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((Host, Port))
    print(f"Connecté au serveur {Host}")
except Exception as e:
    print(f"Erreur de connexion : {e}")
    exit()

reception = Thread(target=receive, args=[client])
reception.daemon = True
reception.start()

lancer_interface(client)

client.close()