"""
interface.py
------------
Interface graphique du client Alpachat (CustomTkinter).

Responsabilités :
  - Afficher les messages reçus dans une zone de chat scrollable.
  - Permettre à l'utilisateur de saisir et d'envoyer des messages.
  - Chiffrer les messages sortants et les signer via HMAC avant envoi.

⚠️  afficher_message() est appelée depuis le thread de réception (receive() dans
    client.py). CustomTkinter n'est pas thread-safe : il faudrait utiliser
    app.after(0, ...) pour déléguer la mise à jour au thread principal.
"""

import customtkinter
import json
import hmac
import hashlib
import crypto
import keygen
import numpy as np

# Variables globales de l'interface
zone_chat = None   # Zone scrollable où les bulles de message sont ajoutées
mon_pseudo = "Anonyme"
app = None         # Fenêtre principale CustomTkinter


def afficher_message(texte, auteur="autre"):
    """
    Ajoute une bulle de message dans la zone de chat.

    Le style de la bulle varie selon l'auteur :
      - "moi"     : alignée à droite, fond bleu
      - "systeme" : centrée, fond gris foncé (messages d'état)
      - "autre"   : alignée à gauche, fond gris (messages reçus)

    ⚠️  Cette fonction peut être appelée depuis un thread non-UI (receive()).
        Tkinter n'étant pas thread-safe, des crashs aléatoires sont possibles.
        Correction recommandée : app.after(0, afficher_message, texte, auteur)

    Paramètres
    ----------
    texte  : str — contenu du message à afficher
    auteur : str — "moi", "systeme" ou "autre" (valeur par défaut)
    """
    # [DEBUG] Tracer chaque appel à afficher_message avec son auteur
    # print(f"[DEBUG afficher_message] auteur='{auteur}' | texte='{texte}'")

    if zone_chat is not None:
        # Définition du style de la bulle selon l'auteur
        if auteur == "moi":
            anchor = "e"
            fg_color = "#1f6aa5"
            txt_color = "white"
        elif auteur == "systeme":
            anchor = "center"
            fg_color = "#4a4a4a"
            txt_color = "#aaaaaa"
        else:
            anchor = "w"
            fg_color = "#3d3d3d"
            txt_color = "white"

        # Création de la bulle (frame arrondie + label texte)
        msg_frame = customtkinter.CTkFrame(zone_chat, fg_color=fg_color, corner_radius=10)
        msg_frame.pack(padx=10, pady=5, anchor=anchor)

        label = customtkinter.CTkLabel(msg_frame, text=texte, text_color=txt_color, wraplength=400, justify="left")
        label.pack(padx=10, pady=5)

        # Défilement automatique vers le bas après ajout d'un message
        zone_chat._parent_canvas.yview_moveto(1.0)
    else:
        # [DEBUG] Avertir si zone_chat n'est pas encore initialisée
        # print("[DEBUG afficher_message] AVERTISSEMENT : zone_chat est None, message ignoré")
        pass


def fermer_interface():
    """
    Ferme proprement la fenêtre CustomTkinter.
    Appelée depuis receive() quand la connexion est perdue.
    """
    # [DEBUG] Tracer l'appel à fermer_interface
    # print("[DEBUG fermer_interface] fermeture de la fenêtre demandée.")
    if app:
        app.quit()
        app.destroy()


def lancer_interface(client_socket, SECRET_DH):
    """
    Initialise et lance la fenêtre principale du chat.

    Cette fonction est bloquante : elle rend la main seulement
    quand l'utilisateur ferme la fenêtre (fin de app.mainloop()).

    Paramètres
    ----------
    client_socket : socket.socket — socket TCP connecté au serveur relais
    SECRET_DH     : int           — secret Diffie-Hellman partagé,
                                    utilisé comme clef HMAC et source des matrices-clefs
    """
    global zone_chat, mon_pseudo, app

    # [DEBUG] Confirmer que l'interface est lancée avec le bon SECRET_DH
    # print(f"[DEBUG lancer_interface] SECRET_DH reçu : {SECRET_DH}")

    customtkinter.set_appearance_mode("dark")
    app = customtkinter.CTk()
    app.geometry("500x700")
    app.title("Alpachat - Sécurisé")

    # Demande du pseudo à l'utilisateur avant d'afficher la fenêtre principale
    dialog = customtkinter.CTkInputDialog(text="Choisissez un pseudo :", title="Connexion")
    res = dialog.get_input()
    mon_pseudo = res if res and res.strip() != "" else "Anonyme"

    # [DEBUG] Confirmer le pseudo choisi
    # print(f"[DEBUG lancer_interface] pseudo choisi : '{mon_pseudo}'")

    # En-tête avec le pseudo choisi
    titre = customtkinter.CTkLabel(app, text=f"Chat sécurisé : {mon_pseudo}", font=("Helvetica", 16, "bold"))
    titre.pack(pady=10)

    # Zone de chat scrollable (les bulles sont ajoutées ici par afficher_message)
    zone_chat = customtkinter.CTkScrollableFrame(app, fg_color="#242424", label_text="Conversation")
    zone_chat.pack(padx=20, pady=(0, 20), fill="both", expand=True)

    # Message système d'accueil
    afficher_message("Connexion établie avec succès.", "systeme")

    def envoyer_message():
        """
        Callback déclenché par le bouton "Envoyer" ou la touche Entrée.

        Étapes :
          1. Lecture du texte saisi.
          2. Dérivation des quatre matrices-clefs depuis SECRET_DH.
          3. Chiffrement du message.
          4. Calcul du HMAC-SHA256 sur le message chiffré.
          5. Envoi du paquet JSON { "ch2": [...], "hmac": "..." }.
          6. Affichage local de la bulle "Moi".
        """
        texte = champ_saisie.get()
        if texte.strip() != "":
            message_complet = f"{mon_pseudo} : {texte}"

            # [DEBUG] Afficher le message complet avant chiffrement
            # print(f"[DEBUG envoyer_message] message clair : '{message_complet}'")

            # Dérivation des clefs à partir du secret DH partagé
            k1, k2, k3, k4 = keygen.generer_matrices_clefs(SECRET_DH)

            # Chiffrement du message
            chiffre = crypto.chiffrement(message_complet, k1, k2, k3, k4)

            # [DEBUG] Afficher la taille du message chiffré
            # print(f"[DEBUG envoyer_message] taille chiffrée : {len(chiffre)} octets")

            # Calcul du HMAC-SHA256 pour garantir l'intégrité du message
            # La clef HMAC est le secret DH, converti en octets
            chiffre_np = np.array(chiffre, dtype=np.int32)
            signature = hmac.new(str(SECRET_DH).encode(), chiffre_np.tobytes(), hashlib.sha256).hexdigest()

            # [DEBUG] Afficher la signature HMAC calculée
            # print(f"[DEBUG envoyer_message] signature HMAC : {signature}")

            # Construction et envoi du paquet
            paquet = {"ch2": chiffre, "hmac": signature}
            try:
                client_socket.send(json.dumps(paquet).encode('utf-8'))

                # [DEBUG] Confirmer l'envoi réseau réussi
                # print(f"[DEBUG envoyer_message] paquet envoyé avec succès.")

                afficher_message(f"Moi : {texte}", "moi")  # Affichage local
                champ_saisie.delete(0, 'end')               # Vidage du champ de saisie
            except Exception as e:
                # [DEBUG] Afficher l'exception réseau pour diagnostiquer
                # print(f"[DEBUG envoyer_message] erreur envoi : {type(e).__name__} — {e}")
                fermer_interface()

    # ── Barre de saisie en bas de fenêtre ──────────────────────────────────
    frame_bas = customtkinter.CTkFrame(app, fg_color="transparent")
    frame_bas.pack(padx=20, pady=10, fill="x", side="bottom")

    champ_saisie = customtkinter.CTkEntry(frame_bas, placeholder_text="Écrivez votre message ici...", height=40)
    champ_saisie.pack(side="left", fill="x", expand=True, padx=(0, 10))
    champ_saisie.bind("<Return>", lambda event: envoyer_message())  # Envoi avec Entrée

    bouton_envoyer = customtkinter.CTkButton(frame_bas, text="Envoyer", width=100, height=40, command=envoyer_message)
    bouton_envoyer.pack(side="right")

    # [DEBUG] Confirmer le démarrage du mainloop
    # print("[DEBUG lancer_interface] démarrage du mainloop.")

    # Boucle principale de l'interface (bloquant jusqu'à fermeture)
    app.mainloop()

    # [DEBUG] Confirmer la sortie du mainloop
    # print("[DEBUG lancer_interface] mainloop terminé.")