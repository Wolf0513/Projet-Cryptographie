import customtkinter
import json
import hmac
import hashlib
import crypto
import numpy as np

zone_chat = None
mon_pseudo = "Anonyme"
app = None

def afficher_message(texte, auteur="autre"):
    if zone_chat is not None:
        # Détermine l'alignement et la couleur selon l'auteur
        if auteur == "moi":
            anchor = "e"
            fg_color = "#1f6aa5" # Bleu
            txt_color = "white"
        elif auteur == "systeme":
            anchor = "center"
            fg_color = "#4a4a4a" # Gris foncé
            txt_color = "#aaaaaa"
        else:
            anchor = "w"
            fg_color = "#3d3d3d" # Gris
            txt_color = "white"

        # Création d'une bulle de message (frame)
        msg_frame = customtkinter.CTkFrame(zone_chat, fg_color=fg_color, corner_radius=10)
        msg_frame.pack(padx=10, pady=5, anchor=anchor)
        
        label = customtkinter.CTkLabel(msg_frame, text=texte, text_color=txt_color, wraplength=400, justify="left")
        label.pack(padx=10, pady=5)
        
        # Scroll automatique vers le bas
        app.update_idletasks()
        canvas.yview_moveto(1.0)

def fermer_interface():
    if app:
        app.quit()
        app.destroy()

def lancer_interface(client_socket, SECRET_DH):
    global zone_chat, mon_pseudo, app, canvas

    customtkinter.set_appearance_mode("dark")
    app = customtkinter.CTk()
    app.geometry("500x700")
    app.title("Alpachat - Sécurisé")

    # Dialogue pseudo
    dialog = customtkinter.CTkInputDialog(text="Choisissez un pseudo :", title="Connexion")
    res = dialog.get_input()
    mon_pseudo = res if res and res.strip() != "" else "Anonyme"

    # Zone de titre
    titre = customtkinter.CTkLabel(app, text=f"Chat sécurisé : {mon_pseudo}", font=("Helvetica", 16, "bold"))
    titre.pack(pady=10)

    # Conteneur scrollable pour les bulles
    canvas = customtkinter.CTkScrollableFrame(app, fg_color="#242424", label_text="Conversation")
    canvas.pack(padx=20, pady=(0, 20), fill="both", expand=True)
    zone_chat = canvas

    afficher_message(f"Connexion établie avec succès.", "systeme")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte.strip() != "":
            message_complet = f"{mon_pseudo} : {texte}"
            
            # Chiffrement et HMAC
            key1, key2 = crypto.generer_matrices_clefs(SECRET_DH)
            chiffre = crypto.chiffrement(message_complet, key1, key2)
            
            chiffre_np = np.array(chiffre, dtype=np.int32)
            signature = hmac.new(str(SECRET_DH).encode(), chiffre_np.tobytes(), hashlib.sha256).hexdigest()
            
            paquet = {"ch2": chiffre, "hmac": signature}
            try:
                client_socket.send(json.dumps(paquet).encode('utf-8'))
                afficher_message(f"Moi : {texte}", "moi")
                champ_saisie.delete(0, 'end')
            except:
                fermer_interface()

    # Barre d'envoi en bas
    frame_bas = customtkinter.CTkFrame(app, fg_color="transparent")
    frame_bas.pack(padx=20, pady=10, fill="x", side="bottom")

    champ_saisie = customtkinter.CTkEntry(frame_bas, placeholder_text="Écrivez votre message ici...", height=40)
    champ_saisie.pack(side="left", fill="x", expand=True, padx=(0, 10))
    champ_saisie.bind("<Return>", lambda event: envoyer_message())
    
    bouton_envoyer = customtkinter.CTkButton(frame_bas, text="Envoyer", width=100, height=40, command=envoyer_message)
    bouton_envoyer.pack(side="right")

    app.mainloop()