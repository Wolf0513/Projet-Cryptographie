import socket
from threading import Thread
import json
import crypto
import keygen
from interface import lancer_interface, afficher_message

Host = "10.1.40.74"
Port = 6390
SECRET_DH = None
connecte = True

def receive(client_socket):
    global connecte
    while connecte:
        try:
            requete = client_socket.recv(8192)
            if requete:
                paquet = json.loads(requete.decode('utf-8'))
                chiffre = paquet['ch2']
                longueur = len(chiffre[0]) * 2
                k1, k2 = keygen.generer_matrices_clefs(SECRET_DH, longueur)
                message = crypto.dechiffrement(chiffre, k1, k2)
                afficher_message(message)
            else:
                connecte = False
        except:
            connecte = False

serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.bind((Host, Port))
serveur.listen(1)

print(f"Serveur en écoute sur {Host}:{Port}...")
client, adresse = serveur.accept()
print(f"Connexion établie avec {adresse}")

try:
    ma_privee = crypto.generer_clef()
    ma_publique = crypto.publique(ma_privee)
    data = client.recv(1024).decode()
    publique_client = int(data)
    client.send(str(ma_publique).encode())
    SECRET_DH = crypto.commun(ma_privee, publique_client)
except:
    client.close()
    serveur.close()
    exit()

reception = Thread(target=receive, args=[client])
reception.daemon = True
reception.start()

lancer_interface(client, SECRET_DH)
connecte = False
client.close()
serveur.close()