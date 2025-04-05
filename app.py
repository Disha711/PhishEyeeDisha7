import pandas as pd
import xgboost as xgb
import numpy as np
from flask import Flask, request, jsonify
import os
import re
import time
import requests
from urllib.parse import urlparse
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from pymongo import MongoClient
from auth import auth_bp
from dotenv import load_dotenv
from feature_extraction import extract_features
import certifi
from flask_cors import CORS  # ✅ Import CORS

# ✅ Load environment variables
load_dotenv()

# ✅ Define Flask app
app = Flask(__name__)

# ✅ Enable CORS for specific frontend (React) origin
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins

# ✅ MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["phishi_eye"]
reports_collection = db["reports"]
urls_collection = db["phishing_urls"]

# ✅ Configure JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your_secret_key")
jwt = JWTManager(app)

# ✅ Register auth blueprint
app.register_blueprint(auth_bp)

# ✅ Lazy Load XGBoost Model
def load_model():
    booster = xgb.Booster()
    booster.load_model("xgboost_model.json")
    return booster

# ✅ Feature Names
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

@app.route("/", methods=["GET"])
def home():
    return "Phishing Detection API is running!", 200

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if "url" not in data:
            return jsonify({"error": "Missing 'url' field in request"}), 400

        url = data["url"]

        # ✅ Check if URL already exists in DB
        existing_entry = urls_collection.find_one({"url": url})
        if existing_entry:
            return jsonify({
                "url": url,
                "prediction": existing_entry["prediction"],
                "confidence": existing_entry.get("confidence"),
                "message": "Fetched from database"
            })

        # ✅ Extract features from URL
        features = extract_features(url)
        if features is None:
            return jsonify({"error": "Feature extraction failed"}), 500

        # ✅ Create DataFrame
        df_input = pd.DataFrame([features], columns=FEATURE_NAMES)

        # ✅ Load model and predict
        booster = load_model()
        dmatrix = xgb.DMatrix(df_input, feature_names=FEATURE_NAMES)
        prediction = booster.predict(dmatrix)

        probability = float(prediction[0])
        result = "Phishing" if probability > 0.5 else "Legitimate"

        # ✅ Store prediction result in MongoDB
        urls_collection.insert_one({
            "url": url,
            "prediction": result,
            "confidence": round(probability, 4),
            "timestamp": time.time()
        })

        return jsonify({
            "url": url,
            "prediction": result,
            "confidence": round(probability, 4)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history", methods=["GET"])
@jwt_required()
def get_history():
    try:
        current_user = get_jwt_identity()
        reports = list(reports_collection.find({"user": current_user}, {"_id": 0}))
        return jsonify({"history": reports}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report", methods=["POST"])
@jwt_required()
def report():
    try:
        data = request.get_json()
        if "url" not in data:
            return jsonify({"error": "Missing 'url' field in request"}), 400

        url = data["url"]

        # ✅ Check if URL exists in DB
        existing_entry = urls_collection.find_one({"url": url})
        if existing_entry:
            result = existing_entry["prediction"]
        else:
            features = extract_features(url)
            if features is None:
                return jsonify({"error": "Feature extraction failed"}), 500

            df_input = pd.DataFrame([features], columns=FEATURE_NAMES)
            dmatrix = xgb.DMatrix(df_input, feature_names=FEATURE_NAMES)

            booster = load_model()
            prediction = booster.predict(dmatrix)
            result = "Phishing" if prediction[0] > 0.5 else "Legitimate"

        current_user = get_jwt_identity()
        reports_collection.insert_one({"user": current_user, "url": url, "prediction": result, "timestamp": time.time()})

        return jsonify({"message": "Report saved successfully", "url": url, "prediction": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
