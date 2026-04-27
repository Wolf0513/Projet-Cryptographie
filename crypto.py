import numpy as np

def chiffrement(message,key1,key2):
    l = len(message)
    matrice = [[ord(message[char]) for char in range(l//2 +1)], 
             [ord(message[char]) for char in range(l//2 +1 , l) ]] 
    
    if len(matrice[0]) != len(matrice[1]):
        for i in range(len(matrice[0])-len(matrice[1])):
            matrice[1].append(0)
    
    tx = np.array(matrice)
    chiffre = tx ^ key1 ^ key2

    return chiffre

def dechiffrement(ch2,key1,key2):
    key1,key2,ch2 = np.array(key1), np.array(key2),np.array(ch2)
    dch = ch2 ^ key2 ^ key1

    txt = ""
    for i in range(dch.shape[0]):
        for j in range(dch.shape[1]):
            txt += chr(dch[i][j])
    return txt