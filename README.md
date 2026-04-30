# Projet-Cryptographie

Alpachat - Messagerie sécurisée E2EE

Alpachat est une application de chat en temps réel permettant à deux utilisateurs de communiquer de manière sécurisée via un serveur relais. Le projet met l'accent sur la confidentialité grâce à un chiffrement de bout en bout (End-to-End Encryption) personnalisé.

Fonctionnalités : 
- Chiffrement E2EE : Les messages sont chiffrés sur le client émetteur et déchiffrés uniquement par le destinataire.

- Échange de clés Diffie-Hellman : Négociation d'un secret partagé sans transmission de clés privées sur le réseau.

- Intégrité garantie : Utilisation de HMAC-SHA256 pour vérifier que les messages n'ont pas été altérés ou rejoués.

- Interface Graphique (GUI) : Interface moderne et sombre (Dark Mode) réalisée avec CustomTkinter.

- Serveur Relais : Un serveur TCP minimaliste qui assure le transit des paquets sans jamais avoir accès au contenu clair.

Architecture Cryptographie 

Le projet implémente sa propre couche de sécurité inspirée des standards industriels :Négociation :
1. Échange de clés Diffie-Hellman (g=248, p=967) pour générer un SECRET_DH.
2. Dérivation de clés : Double hachage SHA-256 du secret pour générer 4 matrices de clés 4*4.
3. Algorithme de Chiffrement : Un cipher par blocs inspiré d'AES comprenant :
    -SubBytes (S-Box non-linéaire)
    -ShiftRows (Diffusion par décalage de lignes)
    -MixColumns (Mélange algébrique dans GF(2**8))
    -AddRoundKey (XOR avec clés dérivées et IV)
4. Authentification : Signature HMAC systématique de chaque paquet chiffré.

Installation 

prérequis :
- python 3.8
- bibliothèque : "pip install customtkinter"

structure du projet : 
    serveur.py : Gère la mise en relation des deux clients.

    client.py : Point d'entrée de l'application utilisateur.

    interface.py : Logique de l'interface graphique.

    crypto.py : Primitives de chiffrement et primitives mathématiques.

    keygen.py : Logique de dérivation des clés.

Utilisation : 

Pour démarrer une session de chat, suivez cet ordre :
    Lancer le serveur : "python serveur.py"
Le serveur attendra la connexion de deux clients.

Lancer le premier client :
    python client.py
Lancer le second client :
    python client.py
Une fois les deux clients connectés, l'interface s'ouvre et l'échange sécurisé peut commencer.
