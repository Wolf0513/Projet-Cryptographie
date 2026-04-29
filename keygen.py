"""
keygen.py
---------
Dérive quatre matrices-clefs 4×4 à partir du secret partagé Diffie-Hellman.

Principe :
  1. SHA-256 du secret  → h1 (32 octets)
  2. SHA-256 de h1      → h2 (32 octets)
  3. Les 32 octets de h1 sont découpés en k1 (16 premiers) et k2 (16 derniers).
  4. Les 32 octets de h2 sont découpés en k3 (16 premiers) et k4 (16 derniers).

Le double hachage garantit que k1/k2 et k3/k4 sont indépendants,
même si le secret DH est court.
"""

import numpy as np
import hashlib


def generer_matrices_clefs(secret_commun):
    """
    Dérive quatre matrices-clefs 4×4 (int32) à partir du secret DH partagé.

    Les matrices sont utilisées par crypto.chiffrement() et crypto.dechiffrement()
    pour construire la clef combinée appliquée à chaque bloc.

    Paramètres
    ----------
    secret_commun : int — secret Diffie-Hellman calculé par crypto.commun()

    Retourne
    --------
    (k1, k2, k3, k4) : tuple de quatre np.ndarray de forme (4, 4), dtype int32
    """
    # Premier hachage : SHA-256 du secret (converti en chaîne puis en octets)
    h1 = hashlib.sha256(str(secret_commun).encode()).digest()  # 32 octets

    # Deuxième hachage : SHA-256 de h1 pour obtenir 32 octets supplémentaires indépendants
    h2 = hashlib.sha256(h1).digest()  # 32 octets

    # [DEBUG] Afficher les deux hashs pour vérifier la dérivation des clefs
    # print(f"[DEBUG keygen] secret_commun : {secret_commun}")
    # print(f"[DEBUG keygen] h1 (hex) : {h1.hex()}")
    # print(f"[DEBUG keygen] h2 (hex) : {h2.hex()}")

    # Découpage de h1 en deux matrices 4×4 de 16 octets chacune
    k1 = np.array(list(h1[:16]), dtype=np.int32).reshape(4, 4)  # octets  0–15 de h1
    k2 = np.array(list(h1[16:]), dtype=np.int32).reshape(4, 4)  # octets 16–31 de h1

    # Découpage de h2 en deux matrices 4×4 de 16 octets chacune
    k3 = np.array(list(h2[:16]), dtype=np.int32).reshape(4, 4)  # octets  0–15 de h2
    k4 = np.array(list(h2[16:]), dtype=np.int32).reshape(4, 4)  # octets 16–31 de h2

    # [DEBUG] Afficher les quatre matrices générées
    # print(f"[DEBUG keygen] k1 :\n{k1}")
    # print(f"[DEBUG keygen] k2 :\n{k2}")
    # print(f"[DEBUG keygen] k3 :\n{k3}")
    # print(f"[DEBUG keygen] k4 :\n{k4}")

    return k1, k2, k3, k4