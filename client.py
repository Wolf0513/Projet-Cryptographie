"""
client.py
---------
Point d'entrée du client Alpachat.

Responsabilités :
  1. Connexion TCP au serveur relais.
  2. Échange de clefs Diffie-Hellman avec l'autre client (via le relais).
  3. Lancement d'un thread de réception qui déchiffre et vérifie les messages.
  4. Lancement de l'interface graphique (bloquant jusqu'à fermeture).

Flux de démarrage :
  connexion TCP
      → envoi clef publique DH
      → réception clef publique distante
      → calcul secret partagé
      → démarrage thread receive()
      → démarrage interface (interface.lancer_interface)
"""

import socket
from threading import Thread
import json
import crypto
import keygen
import hmac
import hashlib
import numpy as np
import interface

# ─────────────────────────────────────────────
# Configuration réseau
# ─────────────────────────────────────────────
Host = "192.168.1.38"
Port = 6390

# Secret DH partagé, calculé après l'échange initial.
# Utilisé par le thread receive() pour vérifier le HMAC et déchiffrer.
# ⚠️  Variable globale partagée entre threads sans verrou (race condition possible).
SECRET_DH = None

# Drapeau de contrôle du thread de réception.
# Passer à False pour arrêter proprement la boucle de receive().
connecte = True


def receive(client_socket):
    """
    Thread de réception : écoute en continu les messages entrants.

    Pour chaque paquet reçu :
      1. Désérialise le JSON  → { "ch2": [...], "hmac": "..." }
      2. Recalcule le HMAC local et le compare au HMAC reçu.
      3. Si le HMAC est valide : déchiffre et affiche le message.
      4. Si le HMAC est invalide : déconnexion immédiate (intégrité compromise).

    Le thread se termine et ferme le socket si :
      - le serveur ferme la connexion (recv retourne b'')
      - une exception réseau est levée
      - le HMAC est invalide
    """
    global connecte

    # [DEBUG] Confirmer que le thread de réception a bien démarré
    # print(f"[DEBUG receive] thread démarré, SECRET_DH={SECRET_DH}")

    while connecte:
        try:
            requete = client_socket.recv(8192)
            if requete:
                # [DEBUG] Afficher la taille brute du paquet reçu
                # print(f"[DEBUG receive] paquet reçu : {len(requete)} octets")

                # Désérialisation du paquet JSON
                paquet = json.loads(requete.decode('utf-8'))
                chiffre_liste = paquet['ch2']    # liste d'entiers : [IV] + [blocs chiffrés]
                hmac_recu = paquet['hmac']        # signature HMAC-SHA256 en hexadécimal

                # [DEBUG] Afficher le HMAC reçu et la taille de la liste chiffrée
                # print(f"[DEBUG receive] hmac reçu    : {hmac_recu}")
                # print(f"[DEBUG receive] taille ch2   : {len(chiffre_liste)} octets")

                # Vérification de l'intégrité via HMAC-SHA256
                # La clef HMAC est le secret DH converti en octets
                chiffre_np = np.array(chiffre_liste, dtype=np.int32)
                secret_bytes = str(SECRET_DH).encode()
                hmac_local = hmac.new(secret_bytes, chiffre_np.tobytes(), hashlib.sha256).hexdigest()

                # [DEBUG] Comparer les deux HMAC avant compare_digest (ne pas laisser en prod)
                # print(f"[DEBUG receive] hmac local   : {hmac_local}")
                # print(f"[DEBUG receive] HMAC {'OK' if hmac_local == hmac_recu else 'INVALIDE'}")

                if hmac.compare_digest(hmac_local, hmac_recu):
                    # HMAC valide → déchiffrement et affichage
                    k1, k2, k3, k4 = keygen.generer_matrices_clefs(SECRET_DH)
                    message = crypto.dechiffrement(chiffre_liste, k1, k2, k3, k4)

                    # [DEBUG] Afficher le message déchiffré avant affichage UI
                    # print(f"[DEBUG receive] message déchiffré : '{message}'")

                    interface.afficher_message(message)
                else:
                    # HMAC invalide → le message a peut-être été altéré ou rejoué
                    print("🚨 HMAC INVALIDE : Déconnexion.")
                    connecte = False
            else:
                # Le serveur a fermé la connexion proprement
                # [DEBUG] Confirmer la déconnexion propre
                # print("[DEBUG receive] connexion fermée par le serveur.")
                connecte = False

        except Exception as e:
            # Erreur réseau ou de parsing → on arrête le thread
            # [DEBUG] Afficher l'exception réelle pour diagnostiquer
            # print(f"[DEBUG receive] exception : {type(e).__name__} — {e}")
            connecte = False

    # Nettoyage : fermeture du socket et de l'interface
    # [DEBUG] Confirmer la fin du thread
    # print("[DEBUG receive] thread terminé, fermeture socket.")
    client_socket.close()
    interface.fermer_interface()


# ─────────────────────────────────────────────
# Connexion et échange Diffie-Hellman
# ─────────────────────────────────────────────
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((Host, Port))

    # [DEBUG] Confirmer la connexion TCP établie
    # print(f"[DEBUG client] connecté à {Host}:{Port}")

    # Génération de la paire de clefs DH locale
    ma_privee = crypto.generer_clef()           # clef privée (jamais transmise)
    ma_pub = crypto.publique(ma_privee)          # clef publique = g^privee mod p

    # [DEBUG] Afficher les clefs DH locales (NE PAS laisser actif en production !)
    # print(f"[DEBUG client] clef privée : {ma_privee}")
    # print(f"[DEBUG client] clef publique envoyée : {ma_pub}")

    # Envoi de la clef publique au serveur relais (qui la transmet à l'autre client)
    # ⚠️  Échange en clair : un attaquant MITM peut intercepter et substituer les clefs
    client.send(str(ma_pub).encode())

    # Réception de la clef publique de l'autre client
    data = client.recv(1024).decode()

    # [DEBUG] Afficher la clef publique reçue de l'autre client
    # print(f"[DEBUG client] clef publique reçue : {data}")

    # Calcul du secret partagé : publique_distante^privee_locale mod p
    SECRET_DH = crypto.commun(ma_privee, int(data))

    # [DEBUG] Confirmer le secret partagé calculé (NE PAS laisser actif en production !)
    # print(f"[DEBUG client] SECRET_DH calculé : {SECRET_DH}")

except Exception as e:
    print(f"Erreur de connexion : {e}")
    exit()

# ─────────────────────────────────────────────
# Démarrage du thread de réception et de l'interface
# ─────────────────────────────────────────────

# [DEBUG] Confirmer le lancement du thread de réception
# print("[DEBUG client] lancement du thread receive...")

# Le thread de réception tourne en arrière-plan (daemon=True : il s'arrête
# automatiquement quand le thread principal se termine)
Thread(target=receive, args=[client], daemon=True).start()

# Lancement de l'interface graphique (bloquant jusqu'à fermeture de la fenêtre)
interface.lancer_interface(client, SECRET_DH)

# Nettoyage après fermeture de l'interface
# [DEBUG] Confirmer la sortie du mainloop
# print("[DEBUG client] interface fermée, arrêt du client.")
connecte = False
client.close()