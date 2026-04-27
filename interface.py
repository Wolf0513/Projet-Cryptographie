import customtkinter
import json
import hmac
import hashlib
import crypto
from tkinter import messagebox

zone_chat = None
mon_pseudo = "Anonyme"
app = None

def afficher_message(texte):
    if zone_chat is not None:
        zone_chat.insert("end", texte + "\n")
        zone_chat.see("end")

def fermer_interface():
    global app
    if app:
        app.quit()
        app.destroy()

def lancer_interface(client_socket, SECRET_DH):
    global zone_chat, mon_pseudo, app

    app = customtkinter.CTk()
    app.geometry("600x500")
    app.title("Alpachat - Sécurisé")

    app.grid_columnconfigure(0, weight=1)
    app.grid_rowconfigure(0, weight=1)

    dialog = customtkinter.CTkInputDialog(text="Entrez votre pseudo :", title="Connexion")
    input_pseudo = dialog.get_input()
    mon_pseudo = input_pseudo if input_pseudo else "Anonyme"

    zone_chat = customtkinter.CTkTextbox(app)
    zone_chat.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
    afficher_message(f"--- Bienvenue {mon_pseudo} ! ---")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte.strip() != "":
            message_complet = f"{mon_pseudo} : {texte}"
            
            # 1. Chiffrement
            key1, key2 = crypto.generer_matrices_clefs(SECRET_DH, len(message_complet))
            chiffre = crypto.chiffrement(message_complet, key1, key2)
            
            # 2. Signature HMAC
            secret_bytes = str(SECRET_DH).encode()
            signature = hmac.new(secret_bytes, chiffre.tobytes(), hashlib.sha256).hexdigest()
            
            paquet = {"ch2": chiffre.tolist(), "hmac": signature}
            
            try:
                client_socket.send(json.dumps(paquet).encode('utf-8'))
                afficher_message(f"Moi : {texte}")
                champ_saisie.delete(0, 'end')
            except:
                fermer_interface()

    frame_bas = customtkinter.CTkFrame(app, fg_color="transparent")
    frame_bas.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
    champ_saisie = customtkinter.CTkEntry(frame_bas, placeholder_text="Votre message...")
    champ_saisie.grid(row=0, column=0, padx=(0, 10), sticky="ew")
    champ_saisie.bind("<Return>", lambda event: envoyer_message())
    
    bouton_envoyer = customtkinter.CTkButton(frame_bas, text="Envoyer", command=envoyer_message)
    bouton_envoyer.grid(row=0, column=1)

    app.mainloop()