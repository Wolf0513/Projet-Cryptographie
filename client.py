import socket
from threading import Thread
import json
import crypto
import keygen
from interface import lancer_interface, afficher_message

Host = "10.1.40.74"
Port = 6390

SECRET_DH = None
condition = True

def receive(client_socket):
    global condition
    while condition:
        try:
            requete = client_socket.recv(8192)
            if not requete:
                condition = False
            paquet = json.loads(requete.decode('utf-8'))
            chiffre = paquet['ch2']
            longueur_message = len(chiffre[0]) * 2
            k1, k2 = keygen.generer_matrices_clefs(SECRET_DH, longueur_message)
            message_dechiffre = crypto.dechiffrement(chiffre, k1, k2)
            afficher_message(message_dechiffre)

        except Exception as e:
            print(f"Erreur de réception : {e}")
            condition  = False

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((Host, Port))
    print(f"Connecté au serveur {Host}")
    ma_privee = crypto.generer_clef()
    ma_publique = crypto.publique(ma_privee)

    client.send(str(ma_publique).encode())

    data = client.recv(1024).decode()
    publique_serveur = int(data)

    SECRET_DH = crypto.commun(ma_privee, publique_serveur)
    print("Secret DH établi avec succès.")

except Exception as e:
    print(f"Erreur lors de l'initialisation : {e}")
    client.close()
    exit()


reception = Thread(target=receive, args=[client])
reception.daemon = True
reception.start()


lancer_interface(client, SECRET_DH)

client.close()