import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# Load dataset
df = pd.read_csv("dataset/website_data.csv")

# Encode target labels (Risk_Label: Secure = 0, Warning = 1, High Risk = 2)
label_encoder = LabelEncoder()
df["Risk_Label"] = label_encoder.fit_transform(df["Risk_Label"])

# Save label mapping for inference use later
label_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
print("🧾 Label Mapping:", label_mapping)

# Separate features and target
X = df.drop("Risk_Label", axis=1)
y = df["Risk_Label"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))
print("📌 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save model
os.makedirs("model", exist_ok=True)
with open("model/security_model.pkl", "wb") as f:
    pickle.dump(model, f)

# Save label encoder
with open("model/label_encoder.pkl", "wb") as f:
    pickle.dump(label_encoder, f)

print("\n✅ Model and label encoder saved to 'model/' folder.")
