# Alpachat

Application de messagerie chiffrée de bout en bout entre deux clients, développée en Python dans le cadre d'un projet de cryptographie.

---

## Présentation

Alpachat permet à deux utilisateurs de communiquer via un serveur relais qui ne voit jamais le contenu des messages. Tout le chiffrement se passe côté client : le serveur ne fait que transmettre des paquets opaques.

L'application implémente from scratch :
- un échange de clefs **Diffie-Hellman** pour établir un secret partagé sans jamais l'envoyer sur le réseau
- un chiffrement par blocs **inspiré d'AES** (SubBytes, ShiftRows, MixColumns en GF(2⁸), XOR avec IV)
- une vérification d'intégrité **HMAC-SHA256** sur chaque message
- une interface graphique **CustomTkinter** avec affichage des pseudos style messagerie

---

## Architecture

```
projet/
├── serveur.py      # Serveur relais TCP (à lancer en premier)
├── client.py       # Point d'entrée client (connexion + thread de réception)
├── interface.py    # Interface graphique CustomTkinter
├── crypto.py       # Primitives cryptographiques (DH, chiffrement, déchiffrement)
└── keygen.py       # Dérivation des matrices-clefs depuis le secret DH
```

### Flux de démarrage

```
Serveur                     Client A                    Client B
   |                            |                           |
   |<--- connexion TCP ----------|                           |
   |<--- connexion TCP ------------------------------------ |
   |                            |                           |
   |        clef publique DH    |                           |
   |<---------------------------|                           |
   |   clef publique DH         |                           |
   |---------------------------------------------->        |
   |                            |                           |
   |        (idem sens inverse pour client B)               |
   |                            |                           |
   |              [ calcul secret partagé côté client ]     |
   |                            |                           |
   |         paquet JSON chiffré + HMAC                     |
   |<---------------------------|                           |
   |--------------------------------------------->         |
   |                            |     [ déchiffrement ]     |
```

---

## Cryptographie

### Échange Diffie-Hellman

À la connexion, chaque client génère une clef privée aléatoire et calcule sa clef publique `g^privee mod p`. Les deux clefs publiques sont échangées via le serveur relais. Chaque client calcule ensuite le secret partagé `publique_distante^privee_locale mod p` — les deux obtiennent la même valeur sans s'être échangé leurs clefs privées.

### Dérivation des clefs

Le secret DH est haché deux fois avec SHA-256 pour produire 64 octets indépendants, découpés en quatre matrices 4×4 (`k1`, `k2`, `k3`, `k4`) utilisées par le chiffrement.

### Chiffrement par blocs

Le message est découpé en blocs de 16 octets. Sur chaque bloc :

1. **SubBytes** — substitution non-linéaire via la S-Box AES
2. **ShiftRows** — décalage circulaire des lignes
3. **MixColumns** — multiplication matricielle dans GF(2⁸)
4. **XOR** — avec la clef combinée et un IV aléatoire

Un IV de 16 octets est généré aléatoirement à chaque message et préfixé au paquet chiffré.

### Intégrité HMAC

Chaque paquet chiffré est signé avec HMAC-SHA256, en utilisant le secret DH comme clef. Le destinataire recalcule le HMAC et le compare avant de déchiffrer — si les deux ne correspondent pas, la connexion est coupée immédiatement.

### Format du paquet transmis

```json
{
  "ch2": [<IV sur 16 octets>, <blocs chiffrés aplatis>],
  "hmac": "<signature HMAC-SHA256 en hexadécimal>"
}
```

---

## Installation

**Prérequis :** Python 3.10+

Installer les dépendances :

```bash
pip install numpy customtkinter
```

---

## Lancement

### 1. Démarrer le serveur

Sur la machine qui héberge le relais :

```bash
python serveur.py
```

Le serveur écoute sur le port `6390` et attend exactement 2 clients avant d'activer le relais.

### 2. Configurer l'IP dans client.py

Ouvrir `client.py` et renseigner l'IP de la machine qui fait tourner le serveur :

```python
Host = "10.1.40.74"  # ← remplacer par l'IP du serveur
Port = 6390
```

Pour trouver l'IP du serveur sous Windows : `ipconfig` → adresse IPv4 de l'interface active.

### 3. Lancer les deux clients

Sur chaque machine (ou deux terminaux différents) :

```bash
python client.py
```

Une boîte de dialogue demande un pseudo au démarrage. Une fois les deux clients connectés, la conversation peut commencer.

---

## Limitations connues

| Élément | Problème | Impact |
|---|---|---|
| `p = 967` (DH) | Prime trop petit, brutable en <1 ms | Sécurité nulle en dehors du contexte pédagogique |
| CBC non chaîné | L'IV ne change pas entre les blocs d'un même message | Deux blocs clairs identiques → même bloc chiffré |
| `random.randint()` | PRNG non cryptographique pour la clef privée DH | Clef potentiellement prédictible |
| Thread-safety UI | `afficher_message()` appelé depuis un thread non-UI | Crashs aléatoires possibles sous charge |
| Pas de reconnexion | Le serveur n'accepte que les 2 premières connexions | Un client déconnecté ne peut pas revenir |

> Ce projet est un exercice pédagogique. Il ne doit pas être utilisé pour des communications réelles nécessitant de la confidentialité.

---

## Dépendances

| Bibliothèque | Usage | Stdlib |
|---|---|---|
| `numpy` | Matrices pour les opérations cryptographiques | Non |
| `customtkinter` | Interface graphique | Non |
| `socket` | Communication TCP | Oui |
| `hashlib` | SHA-256 pour HMAC et dérivation des clefs | Oui |
| `hmac` | Vérification d'intégrité des messages | Oui |
| `threading` | Thread de réception en parallèle de l'UI | Oui |
| `os` | Génération de l'IV aléatoire (`os.urandom`) | Oui |
| `json` | Sérialisation des paquets | Oui |