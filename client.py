import socket 
from threading import Thread
from crypto import chiffrement
from keygen import gen_clef
import json
Host = "10.40.10.74"
Port = 6390


def send(socket):
    while True:
        message = input("-")
        key1,key2 = gen_clef(len(message))
        chiffre = chiffrement(message,key1,key2)
        paquet = {"ch2":chiffre.tolist(), "key1": key1.tolist(), "key2": key2.tolist()}
        socket.send(json.dumps(paquet).encode('utf-8'))



def receive(socket):
    while True:
        requete_server = socket.recv(500)
        requete_server = requete_server.decode('utf-8')
        print(requete_server)
#Création du Socket *

socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

socket.connect((Host,Port))

#permet d'envoyer plusieurs message à la suite sans attendre la réponse de l'autre
envoi = Thread(target = send, args = [socket])
reception = Thread(target = receive, args = [socket])

envoi.start()
reception.start()

