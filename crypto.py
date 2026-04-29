import numpy as np
import random
import hashlib

p = 967
g = 248

def generer_clef():
    return random.randint(1, p-1)

def publique(privee):
    return pow(g, privee, p)

def commun(privee_locale, publique_distante):
    return pow(publique_distante, privee_locale, p)

def generer_matrices_clefs(secret_commun):
    hash_obj = hashlib.sha256(str(secret_commun).encode()).digest()
    partie1 = list(hash_obj[:16])
    partie2 = list(hash_obj[16:])
    k1 = np.array(partie1, dtype=np.int32).reshape(4, 4)
    k2 = np.array(partie2, dtype=np.int32).reshape(4, 4)
    return k1, k2

def chiffrement(message, k1, k2):
    donnees = [ord(c) for c in message]
    while len(donnees) % 16 != 0:
        donnees.append(0)
    
    resultat = []
    for i in range(0, len(donnees), 16):
        bloc = np.array(donnees[i:i+16], dtype=np.int32).reshape(4, 4)
        chiffre = bloc ^ k1 ^ k2
        resultat.extend(chiffre.flatten().tolist())
    return resultat

def dechiffrement(liste_chiffree, k1, k2):
    donnees = np.array(liste_chiffree, dtype=np.int32)
    resultat_texte = ""
    for i in range(0, len(donnees), 16):
        bloc = donnees[i:i+16].reshape(4, 4)
        dechiffre = bloc ^ k2 ^ k1
        for val in dechiffre.flatten():
            if val != 0:
                resultat_texte += chr(int(val))
    return resultat_texte