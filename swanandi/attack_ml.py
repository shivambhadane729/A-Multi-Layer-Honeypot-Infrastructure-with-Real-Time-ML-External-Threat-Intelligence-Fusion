import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# 1. Load the Data
file_path = 'swanandi/attack_logs_intern.csv'  # <-- your file

try:
    df = pd.read_csv(file_path)
    print("Dataset loaded successfully.")
except FileNotFoundError:
    print(f"File not found: {file_path}. Check the path.")
    exit()

# 2. Preprocessing
df.columns = df.columns.str.strip()  # clean column names

# Check columns
print("Columns found:", df.columns.tolist())

# Your dataset columns:
# ['IP', 'start', 'end', 'duration', 'activity', 'activityID', 'errorcode', 'description']

# Target column (label)
TARGET_COL = 'activity'

if TARGET_COL not in df.columns:
    print(f"ERROR: Target column '{TARGET_COL}' not found.")
    print("Available columns:", df.columns.tolist())
    exit()

# Drop columns that should not be used as ML features
cols_to_drop = [
    'description',     # text description
    'IP',              # identifier, not a feature
    'start',           # timestamps as strings
    'end',             # timestamps as strings
]

df_clean = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')

# Separate X and y
y = df_clean[TARGET_COL]
X = df_clean.drop(columns=[TARGET_COL])

# 3. Encode categorical fields
label_encoders = {}

for col in X.columns:
    if X[col].dtype == "object":
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le

# Encode target labels
le_target = LabelEncoder()
y = le_target.fit_transform(y.astype(str))

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 5. Train Random Forest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

print(f"Training Random Forest on {X_train.shape[0]} samples...")
rf_model.fit(X_train, y_train)
print("Training complete.")

# 6. Evaluation
print("Evaluating model...")
y_pred = rf_model.predict(X_test)

target_names = [str(cls) for cls in le_target.classes_]

print("\n--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))

print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))

# 7. Feature Importance
if hasattr(rf_model, 'feature_importances_'):
    print("\n--- Feature Importance ---")
    importances = rf_model.feature_importances_
    for name, imp in sorted(zip(X.columns, importances), key=lambda x: x[1], reverse=True):
        print(f"{name}: {imp:.4f}")
