import socket 
from threading import Thread
from crypto import dechiffrement 
import json
from interface import lancer_interface, afficher_message

Host = "10.1.40.74"
Port = 6390 


        

def receive(client):
    while True:
        try:
            requete_client = client.recv(8192)
            if not requete_client: 
                print("Connexion perdue")
                break

            # Décodage du JSON reçu
            paquet = json.loads(requete_client.decode('utf-8'))
            
            # Déchiffrement avec tes fonctions de crypto.py
            message_dechiffre = dechiffrement(paquet['ch2'], paquet['key1'], paquet['key2'])
            
            # ON ENVOIE VERS L'INTERFACE
            afficher_message(f"Client : {message_dechiffre}")

        except Exception as e:
            print(f"Erreur de réception : {e}")
            break


serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

serveur.bind((Host, Port))
serveur.listen(1)
print(f"Le serveur écoute en attente d'une connexion sur {Host}:{Port}...")


client, addresseClient = serveur.accept()
print(f"\nConnexion établie avec {addresseClient}")


reception = Thread(target=receive, args=[client])
reception.daemon = True
reception.start()


lancer_interface(client)


client.close()
serveur.close()