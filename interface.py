import customtkinter
import json
import hmac
import hashlib
import crypto
import keygen
import numpy as np

zone_chat = None
mon_pseudo = "Anonyme"
app = None

def afficher_message(texte, auteur="autre"):
    if zone_chat is not None:
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

        msg_frame = customtkinter.CTkFrame(zone_chat, fg_color=fg_color, corner_radius=10)
        msg_frame.pack(padx=10, pady=5, anchor=anchor)
        
        label = customtkinter.CTkLabel(msg_frame, text=texte, text_color=txt_color, wraplength=400, justify="left")
        label.pack(padx=10, pady=5)
        
        # Scroll automatique vers le bas (méthode compatible CTkScrollableFrame)
        zone_chat._parent_canvas.yview_moveto(1.0)

def fermer_interface():
    if app:
        app.quit()
        app.destroy()

def lancer_interface(client_socket, SECRET_DH):
    global zone_chat, mon_pseudo, app

    customtkinter.set_appearance_mode("dark")
    app = customtkinter.CTk()
    app.geometry("500x700")
    app.title("Alpachat - Sécurisé")

    dialog = customtkinter.CTkInputDialog(text="Choisissez un pseudo :", title="Connexion")
    res = dialog.get_input()
    mon_pseudo = res if res and res.strip() != "" else "Anonyme"

    titre = customtkinter.CTkLabel(app, text=f"Chat sécurisé : {mon_pseudo}", font=("Helvetica", 16, "bold"))
    titre.pack(pady=10)

    # Création de la zone de chat scrollable
    zone_chat = customtkinter.CTkScrollableFrame(app, fg_color="#242424", label_text="Conversation")
    zone_chat.pack(padx=20, pady=(0, 20), fill="both", expand=True)

    afficher_message("Connexion établie avec succès.", "systeme")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte.strip() != "":
            message_complet = f"{mon_pseudo} : {texte}"
            
            key1, key2 = keygen.generer_matrices_clefs(SECRET_DH)
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

    frame_bas = customtkinter.CTkFrame(app, fg_color="transparent")
    frame_bas.pack(padx=20, pady=10, fill="x", side="bottom")

    champ_saisie = customtkinter.CTkEntry(frame_bas, placeholder_text="Écrivez votre message ici...", height=40)
    champ_saisie.pack(side="left", fill="x", expand=True, padx=(0, 10))
    champ_saisie.bind("<Return>", lambda event: envoyer_message())
    
    bouton_envoyer = customtkinter.CTkButton(frame_bas, text="Envoyer", width=100, height=40, command=envoyer_message)
    bouton_envoyer.pack(side="right")

    app.mainloop()