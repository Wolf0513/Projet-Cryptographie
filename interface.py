import customtkinter
import json
import crypto
import keygen

zone_chat = None
mon_pseudo = "Anonyme"

def afficher_message(texte):
    if zone_chat is not None:
        zone_chat.insert("end", texte + "\n")
        zone_chat.see("end")

def lancer_interface(client_socket, SECRET_DH):
    global zone_chat, mon_pseudo

    customtkinter.set_appearance_mode("system")
    customtkinter.set_default_color_theme("blue")

    app = customtkinter.CTk()
    app.geometry("600x500")
    app.title("Alpachat")

    
    app.grid_columnconfigure(0, weight=1)
    app.grid_rowconfigure(0, weight=1)

    
    dialog = customtkinter.CTkInputDialog(text="Entrez votre pseudo :", title="Connexion")
    input_pseudo = dialog.get_input()
    if input_pseudo:
        mon_pseudo = input_pseudo

    
    zone_chat = customtkinter.CTkTextbox(app)
    zone_chat.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
    
    afficher_message(f"--- Bienvenue {mon_pseudo} ! ---")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte != "":
            
            message_complet = f"{mon_pseudo} : {texte}"
            
            
            key1, key2 = keygen.generer_matrices_clefs(SECRET_DH, len(message_complet))
            chiffre = crypto.chiffrement(message_complet, key1, key2)
            
            
            paquet = {
                "ch2": chiffre.tolist(), 
            }
            
            client_socket.send(json.dumps(paquet).encode('utf-8'))
            
            afficher_message(f"Moi : {texte}") 
            champ_saisie.delete(0, 'end')

    frame_bas = customtkinter.CTkFrame(app, fg_color="transparent")
    frame_bas.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
    frame_bas.grid_columnconfigure(0, weight=1)

    champ_saisie = customtkinter.CTkEntry(frame_bas, placeholder_text="Votre message...")
    champ_saisie.grid(row=0, column=0, padx=(0, 10), sticky="ew")

    champ_saisie.bind("<Return>", lambda event: envoyer_message())

    bouton_envoyer = customtkinter.CTkButton(frame_bas, text="Envoyer", command=envoyer_message)
    bouton_envoyer.grid(row=0, column=1)

    app.mainloop()