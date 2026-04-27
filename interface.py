import customtkinter
import json
from crypto import chiffrement
from keygen import gen_clef

zone_chat = None
mon_pseudo = "Anonyme" # Pseudo par défaut

def afficher_message(texte):
    if zone_chat is not None:
        zone_chat.insert("end", texte + "\n")

def lancer_interface(client_socket):
    global zone_chat, mon_pseudo

    customtkinter.set_appearance_mode("system")
    customtkinter.set_default_color_theme("blue")

    app = customtkinter.CTk()
    app.geometry("600x500")
    app.title("Alpachat")

    # Demander le pseudo à l'ouverture
    dialog = customtkinter.CTkInputDialog(text="Entrez votre pseudo :", title="Connexion")
    entree_pseudo = dialog.get_input()
    if entree_pseudo:
        mon_pseudo = entree_pseudo

    zone_chat = customtkinter.CTkTextbox(app, width=550, height=350)
    zone_chat.pack(pady=20)
    
    afficher_message(f"--- Bienvenue {mon_pseudo} ! ---")

    def envoyer_message():
        texte = champ_saisie.get()
        if texte != "":
            # On prépare le texte avec le pseudo pour l'autre
            message_complet = f"{mon_pseudo} : {texte}"
            
            # Chiffrement du message complet
            key1, key2 = gen_clef(len(message_complet))
            chiffre = chiffrement(message_complet, key1, key2)
            
            paquet = {
                "ch2": chiffre.tolist(), 
                "key1": key1.tolist(), 
                "key2": key2.tolist()
            }
            
            client_socket.send(json.dumps(paquet).encode('utf-8'))
            
            # On l'affiche aussi chez nous
            afficher_message(f"Moi : {texte}") 
            champ_saisie.delete(0, 'end')

    champ_saisie = customtkinter.CTkEntry(app, width=400, placeholder_text="Message...")
    champ_saisie.pack(side="left", padx=20, pady=20)

    bouton_envoyer = customtkinter.CTkButton(app, text="Envoyer", command=envoyer_message)
    bouton_envoyer.pack(side="right", padx=20, pady=20)

    app.mainloop()