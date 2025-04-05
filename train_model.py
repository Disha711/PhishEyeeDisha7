import pandas as pd
import xgboost as xgb
import pickle

# Load dataset
df = pd.read_csv("phishing_dataset1.csv")

# Define features and target
X = df.drop(columns=["Result"])
y = df["Result"]

# Train XGBoost model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss")
model.fit(X, y)

# Save model as JSON
model.get_booster().save_model("xgboost_model.json")

print("✅ Model trained and saved successfully!")
