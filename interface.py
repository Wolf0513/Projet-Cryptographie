import customtkinter
import json
import hmac
import hashlib
import crypto
import numpy as np

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

    dialog = customtkinter.CTkInputDialog(text="Entrez votre pseudo :", title="Connexion")
    input_pseudo = dialog.get_input()
    mon_pseudo = input_pseudo if input_pseudo else "Anonyme"

    zone_chat = customtkinter.CTkTextbox(app)
    zone_chat.pack(padx=20, pady=20, fill="both", expand=True)

    def envoyer_message():
        texte = champ_saisie.get()
        if texte.strip() != "":
            message_complet = f"{mon_pseudo} : {texte}"
            key1, key2 = crypto.generer_matrices_clefs(SECRET_DH)
            chiffre = crypto.chiffrement(message_complet, key1, key2)
            
            chiffre_np = np.array(chiffre, dtype=np.int32)
            signature = hmac.new(str(SECRET_DH).encode(), chiffre_np.tobytes(), hashlib.sha256).hexdigest()
            
            paquet = {"ch2": chiffre, "hmac": signature}
            try:
                client_socket.send(json.dumps(paquet).encode('utf-8'))
                afficher_message(f"Moi : {texte}")
                champ_saisie.delete(0, 'end')
            except:
                fermer_interface()

    champ_saisie = customtkinter.CTkEntry(app, placeholder_text="Votre message...")
    champ_saisie.pack(padx=20, pady=10, fill="x")
    champ_saisie.bind("<Return>", lambda event: envoyer_message())
    
    app.mainloop()