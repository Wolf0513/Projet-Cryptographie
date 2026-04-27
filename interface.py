import customtkinter

zone_chat = None

def afficher_message(texte):
    if zone_chat is not None:
        zone_chat.insert("end", texte + "\n")

def lancer_interface(client_socket):
    global zone_chat

    customtkinter.set_appearance_mode("system")
    customtkinter.set_default_color_theme("blue")

    app = customtkinter.CTk()
    app.geometry("600x500")
    app.title("Alpachat")
    
    zone_chat = customtkinter.CTkTextbox(app, width=550, height=350)
    zone_chat.pack(pady=20)
    
    afficher_message("--- Connexion établie, le chat est ouvert ! ---")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte != "":
            message_encode = texte.encode('utf-8')
            client_socket.send(message_encode)
            afficher_message(f"Moi : {texte}") 
            champ_saisie.delete(0, 'end')

    champ_saisie = customtkinter.CTkEntry(app, width=400, placeholder_text="Message...")
    champ_saisie.pack(side="left", padx=20, pady=20)

    bouton_envoyer = customtkinter.CTkButton(app, text="Envoyer", command=envoyer_message)
    bouton_envoyer.pack(side="right", padx=20, pady=20)

    app.mainloop()