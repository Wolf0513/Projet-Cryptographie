"""
crypto.py
---------
Fournit toutes les primitives cryptographiques du projet :
  - Échange de clefs Diffie-Hellman (génération, clef publique, secret partagé)
  - Chiffrement / déchiffrement par blocs inspiré d'AES
    (SubBytes, ShiftRows, MixColumns, XOR avec clef combinée et IV)

⚠️  Limitations connues :
  - p=967 est trop petit pour un usage réel (brutable en <1 ms).
  - MATRICE_INV_MIX utilise np.linalg.pinv() (flottant) au lieu de
    l'inverse exacte dans GF(2⁸) → risque d'erreurs d'arrondi.
  - Le mode CBC n'est pas chaîné (l'IV ne change pas entre les blocs).
"""

import numpy as np
import random
import hashlib
import os

# ─────────────────────────────────────────────
# Paramètres Diffie-Hellman
# p : nombre premier (module), g : générateur
# ⚠️  p=967 est trop petit pour un usage réel.
#     En production, utiliser un prime d'au moins 2048 bits.
# ─────────────────────────────────────────────
p = 967
g = 248

# ─────────────────────────────────────────────
# S-Box AES (substitution non-linéaire)
# Tableau de 256 entrées : SBOX[x] donne le substitut de l'octet x.
# Utilisée dans SubBytes pour introduire de la confusion.
# ─────────────────────────────────────────────
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# S-Box inverse : RSBOX[SBOX[x]] == x pour tout x dans [0, 255].
# Construite automatiquement à partir de SBOX pour garantir la cohérence.
# Utilisée dans InvSubBytes lors du déchiffrement.
RSBOX = [0] * 256
for i in range(256):
    RSBOX[SBOX[i]] = i

# ─────────────────────────────────────────────
# Matrices MixColumns
# MATRICE_MIX     : multiplie chaque colonne du bloc (diffusion).
# MATRICE_INV_MIX : inverse utilisée au déchiffrement.
# ⚠️  np.linalg.pinv() donne une pseudo-inverse en virgule flottante.
#     L'inverse exacte dans GF(2⁸) nécessiterait une arithmétique
#     polynomiale modulo 0x11b — des erreurs d'arrondi peuvent survenir.
# ─────────────────────────────────────────────
MATRICE_MIX = np.array([
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
], dtype=np.int32)

MATRICE_INV_MIX = np.linalg.pinv(MATRICE_MIX)  # ⚠️  Approximation flottante

# [DEBUG] Vérifier que RSBOX est bien l'inverse de SBOX (doit afficher True)
# print(f"[DEBUG crypto] RSBOX valide : {all(RSBOX[SBOX[i]] == i for i in range(256))}")

# [DEBUG] Afficher les matrices clefs pour vérifier leur contenu au chargement
# print(f"[DEBUG crypto] MATRICE_MIX :\n{MATRICE_MIX}")
# print(f"[DEBUG crypto] MATRICE_INV_MIX :\n{np.round(MATRICE_INV_MIX, 4)}")


# ─────────────────────────────────────────────
# SubBytes / InvSubBytes
# ─────────────────────────────────────────────

def substituer_octets(matrice):
    """
    SubBytes : remplace chaque octet de la matrice 4×4 par sa valeur dans SBOX.
    Apporte de la confusion (relation non-linéaire entre clair et chiffré).
    """
    resultat = np.array([SBOX[int(x) % 256] for x in matrice.flatten()], dtype=np.int32).reshape(4, 4)
    # [DEBUG] Afficher la matrice avant/après substitution
    # print(f"[DEBUG SubBytes] entrée :\n{matrice}\n→ sortie :\n{resultat}")
    return resultat

def restaurer_octets(matrice):
    """
    InvSubBytes : opération inverse de substituer_octets, via RSBOX.
    """
    resultat = np.array([RSBOX[int(x) % 256] for x in matrice.flatten()], dtype=np.int32).reshape(4, 4)
    # [DEBUG] Afficher la matrice avant/après substitution inverse
    # print(f"[DEBUG InvSubBytes] entrée :\n{matrice}\n→ sortie :\n{resultat}")
    return resultat


# ─────────────────────────────────────────────
# ShiftRows / InvShiftRows
# ─────────────────────────────────────────────

def diffuser_lignes(matrice):
    """
    ShiftRows : décale circulairement chaque ligne i de i positions vers la gauche.
      - Ligne 0 : aucun décalage
      - Ligne 1 : décalage de 1 vers la gauche
      - Ligne 2 : décalage de 2 vers la gauche
      - Ligne 3 : décalage de 3 vers la gauche
    Apporte de la diffusion en mélangeant les octets entre les colonnes.
    """
    m_copy = matrice.copy()
    for i in range(4):
        m_copy[i] = np.roll(m_copy[i], -i)
    # [DEBUG] Afficher la matrice avant/après ShiftRows
    # print(f"[DEBUG ShiftRows] entrée :\n{matrice}\n→ sortie :\n{m_copy}")
    return m_copy

def rassembler_lignes(matrice):
    """
    InvShiftRows : décale circulairement chaque ligne i de i positions vers la droite.
    Opération inverse de diffuser_lignes.
    """
    m_copy = matrice.copy()
    for i in range(4):
        m_copy[i] = np.roll(m_copy[i], i)
    # [DEBUG] Afficher la matrice avant/après InvShiftRows
    # print(f"[DEBUG InvShiftRows] entrée :\n{matrice}\n→ sortie :\n{m_copy}")
    return m_copy


# ─────────────────────────────────────────────
# MixColumns / InvMixColumns
# ─────────────────────────────────────────────

def melanger_colonnes(matrice):
    """
    MixColumns : multiplie chaque colonne par MATRICE_MIX modulo 256.
    Renforce la diffusion entre les octets d'une même colonne.
    """
    resultat = (MATRICE_MIX @ matrice) % 256
    # [DEBUG] Afficher la matrice avant/après MixColumns
    # print(f"[DEBUG MixColumns] entrée :\n{matrice}\n→ sortie :\n{resultat}")
    return resultat

def demeler_colonnes(matrice):
    """
    InvMixColumns : applique MATRICE_INV_MIX puis arrondit au plus proche entier.
    ⚠️  Approximation flottante — des erreurs d'arrondi peuvent corrompre
        silencieusement certains blocs lors du déchiffrement.
    """
    res = MATRICE_INV_MIX @ matrice
    resultat = np.round(res).astype(np.int32) % 256
    # [DEBUG] Afficher les valeurs flottantes brutes pour détecter les erreurs d'arrondi
    # print(f"[DEBUG InvMixColumns] valeurs flottantes brutes :\n{np.round(res, 3)}")
    # print(f"[DEBUG InvMixColumns] après arrondi :\n{resultat}")
    return resultat


# ─────────────────────────────────────────────
# Diffie-Hellman
# ─────────────────────────────────────────────

def generer_clef():
    """
    Génère une clef privée DH : entier aléatoire dans [1, p-1].
    ⚠️  random.randint() est un PRNG non cryptographique.
        Préférer secrets.randbelow(p - 1) + 1 en production.
    """
    clef = random.randint(1, p - 1)
    # [DEBUG] Afficher la clef privée générée (NE PAS laisser actif en production !)
    # print(f"[DEBUG DH] clef privée générée : {clef}")
    return clef

def publique(privee):
    """
    Calcule la clef publique DH : g^privee mod p.
    Cette valeur est envoyée en clair à l'autre partie lors de l'échange initial.
    """
    pub = pow(g, privee, p)
    # [DEBUG] Afficher la clef publique calculée
    # print(f"[DEBUG DH] clef publique calculée : {pub}  (g={g}, privee={privee}, p={p})")
    return pub

def commun(privee_locale, publique_distante):
    """
    Calcule le secret partagé DH : publique_distante^privee_locale mod p.
    Les deux parties obtiennent la même valeur sans s'échanger leurs clefs privées.
    """
    secret = pow(publique_distante, privee_locale, p)
    # [DEBUG] Afficher le secret partagé calculé (NE PAS laisser actif en production !)
    # print(f"[DEBUG DH] secret partagé calculé : {secret}")
    return secret


# ─────────────────────────────────────────────
# Chiffrement / Déchiffrement
# ─────────────────────────────────────────────

def chiffrement(message, k1, k2, k3, k4):
    """
    Chiffre un message texte avec les quatre matrices-clefs issues de keygen.

    Étapes appliquées à chaque bloc de 16 octets :
      1. SubBytes       — substitution non-linéaire via SBOX
      2. ShiftRows      — décalage des lignes pour la diffusion
      3. MixColumns     — mélange des colonnes
      4. XOR            — avec la clef combinée et l'IV

    Un IV de 16 octets aléatoires est généré par message et préfixé
    au résultat pour permettre le déchiffrement côté réception.

    ⚠️  L'IV n'est pas mis à jour entre les blocs (CBC non chaîné) :
        deux blocs clairs identiques produiront le même bloc chiffré.

    Paramètres
    ----------
    message         : str          — texte clair à chiffrer
    k1, k2, k3, k4 : np.ndarray   — matrices 4×4 issues de keygen.generer_matrices_clefs()

    Retourne
    --------
    list[int] — [IV (16 octets)] + [blocs chiffrés aplatis]
    """
    # Génération d'un IV aléatoire de 16 octets (renouvelé à chaque appel)
    iv = os.urandom(16)
    iv_matrix = np.array(list(iv), dtype=np.int32).reshape(4, 4)

    # [DEBUG] Afficher l'IV généré en hexadécimal
    # print(f"[DEBUG chiffrement] IV généré : {iv.hex()}")

    # Conversion du message en liste d'entiers ASCII
    donnees = [ord(c) for c in message]

    # [DEBUG] Afficher la longueur du message avant et après padding
    # print(f"[DEBUG chiffrement] longueur message avant padding : {len(donnees)}")

    # Padding nul pour aligner la longueur sur un multiple de 16
    # ⚠️  Un padding nul est ambigu : les vrais '\x00' du message seront perdus
    while len(donnees) % 16 != 0:
        donnees.append(0)

    # [DEBUG] Afficher la longueur après padding et le nombre de blocs
    # print(f"[DEBUG chiffrement] longueur après padding : {len(donnees)} → {len(donnees) // 16} bloc(s)")

    # Précalcul de la clef combinée (identique pour tous les blocs du message)
    # Formule : ShiftRows( (k1 XOR ShiftRows(k2)) XOR (k3 XOR ShiftRows(k4)) )
    k_combinee = diffuser_lignes((k1 ^ diffuser_lignes(k2)) ^ (k3 ^ diffuser_lignes(k4)))

    # [DEBUG] Afficher la clef combinée utilisée pour le chiffrement
    # print(f"[DEBUG chiffrement] clef combinée :\n{k_combinee}")

    resultat = list(iv)  # L'IV est transmis en clair en tête du paquet

    for i in range(0, len(donnees), 16):
        bloc = np.array(donnees[i:i + 16], dtype=np.int32).reshape(4, 4)

        # [DEBUG] Afficher chaque bloc clair avant transformation
        # print(f"[DEBUG chiffrement] bloc {i // 16} clair :\n{bloc}")

        bloc = substituer_octets(bloc)        # SubBytes
        bloc = diffuser_lignes(bloc)          # ShiftRows
        bloc = melanger_colonnes(bloc)        # MixColumns
        chiffre = bloc ^ k_combinee ^ iv_matrix  # AddRoundKey + XOR IV

        # [DEBUG] Afficher chaque bloc après chiffrement complet
        # print(f"[DEBUG chiffrement] bloc {i // 16} chiffré :\n{chiffre}")

        resultat.extend(chiffre.flatten().tolist())

    # [DEBUG] Afficher la taille totale du paquet chiffré (IV + blocs)
    # print(f"[DEBUG chiffrement] taille paquet final : {len(resultat)} octets")

    return resultat


def dechiffrement(liste_chiffree, k1, k2, k3, k4):
    """
    Déchiffre une liste d'octets produite par chiffrement().

    Étapes appliquées à chaque bloc (ordre strictement inverse du chiffrement) :
      1. XOR            — avec la clef combinée et l'IV
      2. InvMixColumns  — inverse du mélange des colonnes
      3. InvShiftRows   — inverse du décalage des lignes
      4. InvSubBytes    — substitution inverse via RSBOX

    Paramètres
    ----------
    liste_chiffree  : list[int]  — [IV (16 octets)] + [blocs chiffrés]
    k1, k2, k3, k4 : np.ndarray — mêmes matrices-clefs que lors du chiffrement

    Retourne
    --------
    str — message déchiffré (les octets nuls de padding sont ignorés)
    """
    # Extraction de l'IV (16 premiers octets) et du corps chiffré
    iv_part = liste_chiffree[:16]
    message_part = liste_chiffree[16:]

    iv_matrix = np.array(iv_part, dtype=np.int32).reshape(4, 4)
    donnees = np.array(message_part, dtype=np.int32)

    # [DEBUG] Afficher l'IV extrait et la taille des données à déchiffrer
    # print(f"[DEBUG dechiffrement] IV extrait : {bytes(iv_part).hex()}")
    # print(f"[DEBUG dechiffrement] {len(message_part)} octets chiffrés → {len(message_part) // 16} bloc(s)")

    # Recalcul de la clef combinée (même formule qu'au chiffrement)
    k_combinee = diffuser_lignes((k1 ^ diffuser_lignes(k2)) ^ (k3 ^ diffuser_lignes(k4)))

    # [DEBUG] Afficher la clef combinée recalculée (doit être identique à celle du chiffrement)
    # print(f"[DEBUG dechiffrement] clef combinée recalculée :\n{k_combinee}")

    resultat_texte = ""
    for i in range(0, len(donnees), 16):
        bloc = donnees[i:i + 16].reshape(4, 4)

        # [DEBUG] Afficher chaque bloc chiffré avant transformation inverse
        # print(f"[DEBUG dechiffrement] bloc {i // 16} chiffré :\n{bloc}")

        dechiffre = bloc ^ k_combinee ^ iv_matrix  # Défaire AddRoundKey + XOR IV
        dechiffre = demeler_colonnes(dechiffre)     # InvMixColumns
        dechiffre = rassembler_lignes(dechiffre)    # InvShiftRows
        dechiffre = restaurer_octets(dechiffre)     # InvSubBytes

        # [DEBUG] Afficher chaque bloc après déchiffrement complet
        # print(f"[DEBUG dechiffrement] bloc {i // 16} déchiffré :\n{dechiffre}")

        for val in dechiffre.flatten():
            if val != 0:  # Suppression du padding nul (⚠️  perd les vrais '\x00')
                resultat_texte += chr(int(val))

    # [DEBUG] Afficher le message reconstitué avant retour
    # print(f"[DEBUG dechiffrement] message reconstitué : '{resultat_texte}'")

    return resultat_texte