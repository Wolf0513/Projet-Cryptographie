import numpy as np
import random
import hashlib
import os

p = 967
g = 248

def generer_clef():
    return random.randint(1, p-1)

def publique(privee):
    return pow(g, privee, p)

def commun(privee_locale, publique_distante):
    return pow(publique_distante, privee_locale, p)



def chiffrement(message, k1, k2, k3):
    iv = os.urandom(16)
    iv_matrix = np.array(list(iv), dtype=np.int32).reshape(4, 4)
    
    donnees = [ord(c) for c in message]
    while len(donnees) % 16 != 0:
        donnees.append(0)
    resultat = list(iv)
    partie_a = k1 ^ np.left_shift(k2, 1)
    partie_b = k3 ^ np.left_shift(k1, 2)
    k_combinee = partie_a ^ partie_b
    
    for i in range(0, len(donnees), 16):
        bloc = np.array(donnees[i:i+16], dtype=np.int32).reshape(4, 4)
        chiffre = bloc ^ k_combinee ^ iv_matrix
        resultat.extend(chiffre.flatten().tolist())
    return resultat

def dechiffrement(liste_chiffree, k1, k2, k3):
    iv_part = liste_chiffree[:16]
    message_part = liste_chiffree[16:]
    
    iv_matrix = np.array(iv_part, dtype=np.int32).reshape(4, 4)
    donnees = np.array(message_part, dtype=np.int32)
    
    # On reconstruit la même clé combinée
    partie_a = k1 ^ np.left_shift(k2, 1)
    partie_b = k3 ^ np.left_shift(k1, 2)
    k_combinee = partie_a ^ partie_b
    
    resultat_texte = ""
    for i in range(0, len(donnees), 16):
        bloc = donnees[i:i+16].reshape(4, 4)
        dechiffre = bloc ^ k_combinee ^ iv_matrix
        for val in dechiffre.flatten():
            if val != 0:
                resultat_texte += chr(int(val))
    return resultat_texte