"""
serveur.py
----------
Serveur relais TCP pour Alpachat.

Rôle : faire transiter les paquets entre exactement deux clients.
Le serveur ne déchiffre rien — il relaie les octets bruts.
Le chiffrement et la vérification HMAC sont entièrement côté client (E2E).

Fonctionnement :
  1. Attendre la connexion de 2 clients.
  2. Dès que les 2 sont connectés, lancer un thread handle_client() pour chacun.
  3. Chaque thread lit en boucle les messages de son client et les redirige
     vers l'autre client.

⚠️  Limitations :
  - La liste clients[] est accédée par plusieurs threads sans verrou (race condition).
  - Le serveur n'accepte aucune nouvelle connexion après les 2 premières.
    Si un client se déconnecte, il ne peut pas se reconnecter.
  - Aucune authentification : les deux premiers arrivants sont acceptés.
"""

import socket
from threading import Thread
import time

# ─────────────────────────────────────────────
# Configuration réseau
# ─────────────────────────────────────────────
Host = "0.0.0.0"
Port = 6390

# Liste des sockets clients connectés.
# ⚠️  Partagée entre threads sans threading.Lock() → race condition possible
#     si un thread itère pendant qu'un autre appelle clients.remove().
clients = []


def handle_client(client_socket):
    """
    Thread de relais pour un client donné.

    Lit en boucle les messages du client et les retransmet
    à tous les autres clients connectés.

    Le thread se termine si :
      - le client ferme la connexion (recv retourne b'')
      - une exception réseau est levée

    Paramètres
    ----------
    client_socket : socket.socket — socket du client à gérer
    """
    # [DEBUG] Confirmer le démarrage du thread de relais pour ce client
    # print(f"[DEBUG handle_client] thread démarré pour le socket {client_socket.getpeername()}")

    while True:
        try:
            msg = client_socket.recv(8192)
            if msg:
                # [DEBUG] Afficher la taille du message reçu et le nombre de destinataires
                # print(f"[DEBUG handle_client] message reçu : {len(msg)} octets → relais vers {len(clients) - 1} client(s)")

                # Relais du message à tous les autres clients
                for c in clients:
                    if c != client_socket:
                        c.send(msg)

                        # [DEBUG] Confirmer l'envoi à chaque destinataire
                        # print(f"[DEBUG handle_client] relayé vers {c.getpeername()}")
            else:
                # Connexion fermée proprement par le client
                # [DEBUG] Confirmer la déconnexion propre
                # print(f"[DEBUG handle_client] client {client_socket.getpeername()} déconnecté proprement.")
                break

        except Exception as e:
            # [DEBUG] Afficher l'exception réseau pour diagnostiquer
            # print(f"[DEBUG handle_client] exception : {type(e).__name__} — {e}")
            break

    # Nettoyage : retrait du client de la liste et fermeture du socket
    if client_socket in clients:
        clients.remove(client_socket)

    # [DEBUG] Afficher le nombre de clients restants après déconnexion
    # print(f"[DEBUG handle_client] client retiré. Clients restants : {len(clients)}")

    client_socket.close()


# ─────────────────────────────────────────────
# Initialisation du serveur
# ─────────────────────────────────────────────
serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_REUSEADDR permet de relancer le serveur immédiatement après un arrêt
# sans attendre l'expiration du TIME_WAIT du système d'exploitation
serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

serveur.bind((Host, Port))
serveur.listen(2)  # File d'attente de 2 connexions maximum

# [DEBUG] Confirmer que le serveur est bien en écoute
# print(f"[DEBUG serveur] socket créé et en écoute sur {Host}:{Port}")

print("Serveur relais en attente de 2 clients...")

# ─────────────────────────────────────────────
# Attente des 2 clients
# ─────────────────────────────────────────────
# ⚠️  La boucle s'arrête définitivement après 2 connexions.
#     Un client déconnecté ne pourra pas se reconnecter.
while len(clients) < 2:
    client, addr = serveur.accept()
    clients.append(client)
    print(f"Client {len(clients)} connecté depuis {addr}.")

    # [DEBUG] Afficher le nombre de clients en attente
    # print(f"[DEBUG serveur] clients connectés : {len(clients)}/2")

print("Les deux clients sont connectés. Activation du relais...")

# Lancement des threads de relais (un par client)
for c in clients:
    Thread(target=handle_client, args=[c], daemon=True).start()

# [DEBUG] Confirmer que les deux threads de relais sont lancés
# print(f"[DEBUG serveur] {len(clients)} threads de relais démarrés.")

# ─────────────────────────────────────────────
# Maintien du processus principal en vie
# ─────────────────────────────────────────────
try:
    while True:
        # [DEBUG] Afficher périodiquement le nombre de clients encore connectés (toutes les 10s)
        # time.sleep(10)
        # print(f"[DEBUG serveur] clients actifs : {len(clients)}")
        time.sleep(1)
except KeyboardInterrupt:
    print("Arrêt du serveur.")
    serveur.close()