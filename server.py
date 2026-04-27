import socket 
from threading import Thread
from crypto import dechiffrement
import json

def send(client):
    while True :
        message = input("-")
        message = message.encode('utf-8')
        client.send(message)

def receive(client):
    while True :
        try:
            requete_client = client.recv(8192)
            if not requete_client: 
                print("Connection Lost")
                break

            paquet = json.loads(requete_client.decode('utf-8'))
            message_dechiffre = dechiffrement(paquet['ch2'], paquet['key1'], paquet['key2'])
            print(message_dechiffre)

        except Exception as e:
            print(f"Error occurred during reception : {e}")
            break

Host = "192.168.1.38"
Port = 6390

#Création du Socket 
socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

socket.bind((Host,Port))
socket.listen(1)

#Le script s'arrête jusqu'a une connection
client, ip = socket.accept()
print(f"Client ip : {ip} is connected")

#permet d'envoyer plusieurs message à la suite sans attendre la réponse de l'autre
envoi = Thread(target = send, args = [client] )
reception = Thread(target = receive, args = [client])

envoi.start()
reception.start()

reception.join() # fait a ce que le client et le socket s arrete que quand la def reception a fini

client.close()
socket.close()