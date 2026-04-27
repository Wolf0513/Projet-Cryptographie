import numpy as np
import random as r 

def gen_clef(len_mess):
    col = len_mess//2 + 1

    key1 = np.array([[r.randint(0,1000)for i in range(col)],
                     [r.randint(0,1000)for i in range(col)]])
    
    key2 = np.zeros_like(key1)
    for i in range(key1.shape[0]):
        key2[i] =np.roll(key1[i], -i)
        
    return key1,key2