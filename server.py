import socket 
from threading import Thread
from crypto import dechiffrement 
import json
from interface import lancer_interface

Host = "10.1.40.74"
Port = 6390 


        

def receive(client):
    while True:
        try:
            requete_client = client.recv(8192)
            if not requete_client: 
                print("Connection Lost")
                break

            paquet = json.loads(requete_client.decode('utf-8'))
            message_dechiffre = dechiffrement(paquet['ch2'], paquet['key1'], paquet['key2'])

        except Exception as e:
            print(f"Error occurred during reception : {e}")
            break


serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

serveur.bind((Host, Port))
serveur.listen(1)
print(f"Le serveur écoute en attente d'une connexion sur {Host}:{Port}...")


client, addresseClient = serveur.accept()
print(f"\nConnexion établie avec {addresseClient}")

reception = Thread(target=receive, args=[client])
reception.start()


lancer_interface(client)

print("Fermeture des connexions...")
client.close()
serveur.close()