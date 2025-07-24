from twilio.rest import Client

# Remplace ces valeurs avec tes identifiants Twilio
account_sid = ''
auth_token = ''
twilio_number = ''

def send_sms(to_number, message):
    client = Client(account_sid, auth_token)
    
    try:
        message = client.messages.create(
            body=message,
            from_=twilio_number,
            to=to_number
        )
        print("✅ Message envoyé avec succès ! SID:", message.sid)
    except Exception as e:
        print("❌ Erreur :", str(e))

# Exemple
if __name__ == "__main__":
    numero = input("Numéro (ex: +2376...) : ")
    texte = input("Message : ")
    send_sms(numero, texte)
