from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import certifi

# Load env variables
load_dotenv()

auth_bp = Blueprint("auth", __name__)

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["phishi_eye"]
users_collection = db["users"]

# Register Route
@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"email": email, "password": hashed_password})

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Login Route
@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        # ✅ Use Flask-JWT-Extended to generate token
        access_token = create_access_token(identity=email)
        return jsonify({"message": "Login successful", "token": access_token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Optional: Protected Test Route
from flask_jwt_extended import jwt_required, get_jwt_identity

@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({"message": "This is a protected route", "user": current_user}), 200
