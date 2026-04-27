import socket
from threading import Thread
import json
import crypto
import hmac
import hashlib
import numpy as np
import interface

Host = "10.1.40.74"
Port = 6390
SECRET_DH = None
connecte = True
serveur = None

def receive(client_socket):
    global connecte, serveur
    while connecte:
        try:
            requete = client_socket.recv(8192)
            if requete:
                paquet = json.loads(requete.decode('utf-8'))
                chiffre_liste = paquet['ch2']
                hmac_recu = paquet['hmac']
                
                # Vérification HMAC
                chiffre_np = np.array(chiffre_liste, dtype=np.int32)
                secret_bytes = str(SECRET_DH).encode()
                hmac_local = hmac.new(secret_bytes, chiffre_np.tobytes(), hashlib.sha256).hexdigest()
                
                if hmac.compare_digest(hmac_local, hmac_recu):
                    longueur = len(chiffre_liste[0]) * 2
                    k1, k2 = crypto.generer_matrices_clefs(SECRET_DH, longueur)
                    message = crypto.dechiffrement(chiffre_liste, k1, k2)
                    interface.afficher_message(message)
                else:
                    print("🚨 VIOLATION HMAC : Fermeture du serveur.")
                    connecte = False
            else:
                connecte = False
        except:
            connecte = False

    # Nettoyage final
    client_socket.close()
    if serveur: serveur.close()
    interface.fermer_interface()

serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serveur.bind((Host, Port))
serveur.listen(1)

print(f"Serveur en écoute sur {Host}...")
client, adresse = serveur.accept()

try:
    ma_privee = crypto.generer_clef()
    data = client.recv(1024).decode()
    client.send(str(crypto.publique(ma_privee)).encode())
    SECRET_DH = crypto.commun(ma_privee, int(data))
except:
    serveur.close()
    exit()

Thread(target=receive, args=[client], daemon=True).start()
interface.lancer_interface(client, SECRET_DH)

connecte = False
serveur.close()