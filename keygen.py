import numpy as np
import random

def generer_matrices_clefs(secret_commun, longueur_message):
    random.seed(secret_commun)
    taille = (longueur_message // 2) + (longueur_message % 2)
    
    key1 = [[random.randint(0, 255) for _ in range(taille)] for _ in range(2)]
    key2 = [[random.randint(0, 255) for _ in range(taille)] for _ in range(2)]
    
    return np.array(key1), np.array(key2)