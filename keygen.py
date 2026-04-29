import numpy as np
import hashlib

def generer_matrices_clefs(secret_commun):
    h1 = hashlib.sha256(str(secret_commun).encode()).digest()
    h2 = hashlib.sha256(h1).digest()
    k1 = np.array(list(h1[:16]), dtype=np.int32).reshape(4, 4)
    k2 = np.array(list(h1[16:]), dtype=np.int32).reshape(4, 4)
    k3 = np.array(list(h2[:16]), dtype=np.int32).reshape(4, 4)
    k4 = np.array(list(h2[16:]), dtype=np.int32).reshape(4, 4)
    return k1, k2, k3, k4