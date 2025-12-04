import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# 1. Load the Dataset
file_path = 'swanandi/CIDDS-001-external-week1.csv'
df = pd.read_csv(file_path)

print(f"Loaded dataset with {df.shape[0]} rows and {df.shape[1]} columns.")

# 2. Data Cleaning & Preprocessing

# FIX: The 'Bytes' column contains strings like "2.1 M". We need numbers.
def clean_bytes_column(x):
    if isinstance(x, str):
        x = x.strip()
        if 'M' in x:
            return float(x.replace('M', '')) * 1_000_000
        elif 'K' in x:
            return float(x.replace('K', '')) * 1_000
        elif 'G' in x:
            return float(x.replace('G', '')) * 1_000_000_000
        else:
            return float(x)
    return x

df['Bytes'] = df['Bytes'].apply(clean_bytes_column)

# 3. Select Features
# We drop metadata that gives away the answer or isn't a traffic feature
cols_to_drop = [
    'Date first seen',    # Timestamp
    'Src IP Addr',        # Anonymized IP 
    'Dst IP Addr',        # Anonymized IP
    'attackType',         # Label (Metadata)
    'attackID',           # Label (Metadata)
    'attackDescription',  # Label (Metadata)
    'Flows',              # Usually 1 for single flows
    'Tos'                 # Type of Service (often all 0)
]

# Drop the columns
X = df.drop(columns=cols_to_drop + ['class'])
y = df['class']

# 4. Encode Non-Numeric Data
# Convert 'Proto' (TCP/UDP) and 'Flags' (.AP...) to numbers
le_proto = LabelEncoder()
X['Proto'] = le_proto.fit_transform(X['Proto'].astype(str))

le_flags = LabelEncoder()
X['Flags'] = le_flags.fit_transform(X['Flags'].astype(str))

# Encode the Target labels
le_target = LabelEncoder()
y_encoded = le_target.fit_transform(y)

# 5. Split and Train
# 80% Training, 20% Testing
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("Training Random Forest...")
rf_model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
rf_model.fit(X_train, y_train)
print("Training complete.")

# 6. Evaluate Performance
y_pred = rf_model.predict(X_test)

# Map numeric predictions back to names ('normal', 'suspicious', etc.)
class_names = le_target.classes_

print("\n--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))

print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=class_names))

# 7. Show Top Features
print("\n--- Feature Importances ---")
for name, imp in sorted(zip(X.columns, rf_model.feature_importances_), key=lambda x: x[1], reverse=True):
    print(f"{name}: {imp:.4f}")