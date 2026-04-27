import customtkinter
customtkinter.set_appearance_mode("system")  # "system", "dark" ou "light"
customtkinter.set_default_color_theme("blue")

# Création de la fenêtre principale
app = customtkinter.CTk()
app.geometry("600x500")
app.title("Mon Chat Sécurisé")

# Lancement de la boucle infinie de l'interface (TOUJOURS à la fin)
app.mainloop()