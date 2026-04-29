import socket
from threading import Thread
import json
import crypto
import keygen
import hmac
import hashlib
import numpy as np
import interface

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
                chiffre_liste = paquet['ch2']
                hmac_recu = paquet['hmac']
                
                chiffre_np = np.array(chiffre_liste, dtype=np.int32)
                secret_bytes = str(SECRET_DH).encode()
                hmac_local = hmac.new(secret_bytes, chiffre_np.tobytes(), hashlib.sha256).hexdigest()
                
                if hmac.compare_digest(hmac_local, hmac_recu):
                    k1, k2, k3, k4  keygen.generer_matrices_clefs(SECRET_DH)
                    message = crypto.dechiffrement(chiffre_liste, k1 , k2 ,k3 ,k4)
                    interface.afficher_message(message)
                else:
                    print("🚨 HMAC INVALIDE : Déconnexion.")
                    connecte = False
            else:
                connecte = False
        except:
            connecte = False
    
    client_socket.close()
    interface.fermer_interface()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((Host, Port))
    ma_privee = crypto.generer_clef()
    ma_pub = crypto.publique(ma_privee)
    
    client.send(str(ma_pub).encode())
    
    data = client.recv(1024).decode()
    SECRET_DH = crypto.commun(ma_privee, int(data))
except Exception as e:
    print(f"Erreur : {e}")
    exit()

Thread(target=receive, args=[client], daemon=True).start()
interface.lancer_interface(client, SECRET_DH)
connecte = False
client.close()