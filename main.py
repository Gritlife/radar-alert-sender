from flask import Flask, request
import os
import base64
from twilio.rest import Client

app = Flask(__name__)

@app.route("/", methods=["POST"])
def receive_message():
    envelope = request.get_json()

    if not envelope:
        return "No message received", 400

    pubsub_message = envelope.get("message")
    if not pubsub_message:
        return "No Pub/Sub message found", 400

    data = pubsub_message.get("data")
    if not data:
        return "No data field", 400

    decoded_message = base64.b64decode(data).decode("utf-8")

    # Twilio setup
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    from_number = os.environ.get("TWILIO_FROM_NUMBER")
    to_number = os.environ.get("ALERT_TO_NUMBER")

    client = Client(account_sid, auth_token)

    client.messages.create(
        body=decoded_message,
        from_=from_number,
        to=to_number
    )

    return "Message processed", 200
