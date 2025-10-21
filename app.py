from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Simulasi data dompet (disimpan di memori, bukan database)
wallets = {
    "Alice": 100.0,
    "Bob": 50.0
}

API_KEY = "rahasia123"  # ubah nanti di render pakai environment variable kalau mau

@app.route("/")
def home():
    return """
    <h2>Simulasi Dompet Digital Sederhana</h2>
    <p>Gunakan API:</p>
    <ul>
        <li>GET /balance?user=Alice</li>
        <li>POST /deposit</li>
        <li>POST /withdraw</li>
    </ul>
    <p>Gunakan header X-API-KEY: rahasia123</p>
    """

@app.route("/balance")
def balance():
    key = request.headers.get("X-API-KEY")
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    user = request.args.get("user")
    if not user or user not in wallets:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user": user, "balance": wallets[user]})

@app.route("/deposit", methods=["POST"])
def deposit():
    key = request.headers.get("X-API-KEY")
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    user = data.get("user")
    amount = float(data.get("amount", 0))

    if user not in wallets:
        wallets[user] = 0.0

    wallets[user] += amount
    return jsonify({"user": user, "new_balance": wallets[user]})

@app.route("/withdraw", methods=["POST"])
def withdraw():
    key = request.headers.get("X-API-KEY")
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    user = data.get("user")
    amount = float(data.get("amount", 0))

    if user not in wallets:
        return jsonify({"error": "User not found"}), 404

    if wallets[user] < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    wallets[user] -= amount
    return jsonify({"user": user, "new_balance": wallets[user]})

# --- Render butuh port dari environment variable ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
