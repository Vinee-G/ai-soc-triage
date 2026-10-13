"""Train the severity model.   python train_model.py"""
import json
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from triage.features import load_alerts, build_features, FEATURE_COLUMNS
from triage.scorer import MODEL_PATH

NAMES = ["Low", "Medium", "High", "Critical"]

with open("data/train_alerts.jsonl") as f:
    df = build_features(load_alerts(f))
df = df.dropna(subset=["label"])
X, y = df[FEATURE_COLUMNS], df["label"].astype(int)

# stratify keeps the rare Critical alerts in both train and test sets
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
model = RandomForestClassifier(n_estimators=150, max_depth=10, class_weight="balanced", random_state=42)
model.fit(X_tr, y_tr)

pred = model.predict(X_te)
print(classification_report(y_te, pred, target_names=NAMES, digits=3))
print("Confusion matrix (rows = real, cols = predicted):")
print(confusion_matrix(y_te, pred))
print("\nMost important features:")
imp = sorted(zip(FEATURE_COLUMNS, model.feature_importances_), key=lambda t: -t[1])[:8]
for name, v in imp:
    print(f"  {name:22s} {v:.3f}")

joblib.dump(model, MODEL_PATH)
print(f"\nSaved model -> {MODEL_PATH}")
