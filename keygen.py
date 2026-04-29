import numpy as np
import hashlib

def generer_matrices_clefs(secret_commun):
    hash = hashlib.sha256(str(secret_commun).encode()).digest()
    partie1 = list(hash[:16])
    partie2 = list(hash[16:])
    k1 = np.array(partie1, dtype=np.int32).reshape(4, 4)
    k2 = np.array(partie2, dtype=np.int32).reshape(4, 4)
    return k1, k2