import numpy as np
import random

p = 967
g = 248

def generer_clef():
    return random.randint(1, p-1)

def publique(privee):
    return pow(g, privee, p)

def commun(privee_locale, publique_distante):
    return pow(publique_distante, privee_locale, p)



def chiffrement(message, key1, key2):
    l = len(message)
    moitie = (l // 2) + (l % 2)
    
    partie1 = [ord(message[char]) for char in range(moitie)]
    partie2 = [ord(message[char]) for char in range(moitie, l)]
    
    # Padding pour égaliser les lignes
    while len(partie2) < len(partie1):
        partie2.append(0)
    
    tx = np.array([partie1, partie2])
    chiffre = tx ^ key1 ^ key2
    return chiffre

def dechiffrement(ch2, key1, key2):
    key1, key2, ch2 = np.array(key1), np.array(key2), np.array(ch2)
    dch = ch2 ^ key2 ^ key1

    txt = ""
    for i in range(dch.shape[0]):
        for j in range(dch.shape[1]):
            valeur = int(dch[i][j])
            if valeur != 0:
                txt += chr(valeur)
    return txt