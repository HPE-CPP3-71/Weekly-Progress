import os
import pandas as pd
import numpy as np
import joblib

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

import tensorflow as tf
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model

from sklearn.metrics import confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt

MODEL_PATH = "network_autoencoder_model.keras"
BUNDLE_PATH = "preprocessing_bundle.pkl"

print("Loading dataset...")
data = pd.read_csv("UNSW_NB15_training-set.csv")
print("Dataset shape:", data.shape)

# Labels
labels = data["label"]

# Drop non-feature columns
drop_cols = ["label"]
if "attack_cat" in data.columns:
    drop_cols.append("attack_cat")

X = data.drop(columns=drop_cols)

# Preprocessing
cat_cols = X.select_dtypes(include=["object"]).columns
num_cols = X.select_dtypes(exclude=["object"]).columns

X[num_cols] = X[num_cols].fillna(X[num_cols].median())
X[cat_cols] = X[cat_cols].fillna("unknown")

X = pd.get_dummies(X, columns=cat_cols)
X = X.replace([np.inf, -np.inf], 0)

labels = labels.loc[X.index]

# LOAD OLD PREPROCESSING 
if os.path.exists(BUNDLE_PATH):
    print("Loading existing preprocessing...")
    bundle = joblib.load(BUNDLE_PATH)
    scaler = bundle["scaler"]
    old_columns = bundle["columns"]

    # Align columns
    for col in old_columns:
        if col not in X.columns:
            X[col] = 0

    X = X[old_columns]

    # Use existing scaler
    X_scaled = scaler.transform(X)

else:
    print("Creating new preprocessing...")
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    old_columns = X.columns.tolist()

# Split Data
normal_data = X_scaled[labels == 0]
attack_data = X_scaled[labels == 1]

X_train, X_val = train_test_split(
    normal_data,
    test_size=0.2,
    random_state=42
)

X_test = np.concatenate([normal_data, attack_data])
y_test = np.concatenate([
    np.zeros(len(normal_data)),
    np.ones(len(attack_data))
])

# LOAD OR CREATE MODEL
if os.path.exists(MODEL_PATH):
    print("Loading existing model for continued training...")
    autoencoder = tf.keras.models.load_model(MODEL_PATH)
else:
    print("Creating new model...")
    input_dim = X_train.shape[1]

    input_layer = Input(shape=(input_dim,))
    encoded = Dense(64, activation="relu")(input_layer)
    encoded = Dense(32, activation="relu")(encoded)
    encoded = Dense(16, activation="relu")(encoded)

    decoded = Dense(32, activation="relu")(encoded)
    decoded = Dense(64, activation="relu")(decoded)
    decoded = Dense(input_dim, activation="sigmoid")(decoded)

    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer="adam", loss="mse")

autoencoder.summary()

# CONTINUE TRAINING
print("\nTraining / Updating model...\n")

autoencoder.fit(
    X_train,
    X_train,
    epochs=50,   # smaller epochs for incremental training
    batch_size=256,
    validation_data=(X_val, X_val),
    shuffle=True
)

# SAVE MODEL (SAFE UPDATE)
autoencoder.save(MODEL_PATH)
print("\n Model updated")

# THRESHOLD UPDATE
train_recon = autoencoder.predict(X_train)
train_mse = np.mean(np.power(X_train - train_recon, 2), axis=1)

threshold = np.mean(train_mse) + 3 * np.std(train_mse)

print("\nUpdated Threshold:", threshold)

# SAVE UPDATED PREPROCESSING
joblib.dump({
    "threshold": threshold,
    "scaler": scaler,
    "columns": old_columns
}, BUNDLE_PATH)

print("\nPreprocessing+threshold updated!")

# Evaluation
reconstructed = autoencoder.predict(X_test)
mse = np.mean(np.power(X_test - reconstructed, 2), axis=1)

y_pred = (mse > threshold).astype(int)
y_true = y_test

print("\nMetrics:\n")
print("Accuracy :", accuracy_score(y_true, y_pred))
print("Precision:", precision_score(y_true, y_pred))
print("Recall   :", recall_score(y_true, y_pred))
print("F1 Score :", f1_score(y_true, y_pred))

print("\nDetailed Report:\n")
print(classification_report(y_true, y_pred))

# ==============================
# CONFUSION MATRIX
# ==============================
cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\nConfusion Matrix:")
print(cm)

print(f"\nTP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")

# TPR, FPR, TNR
tpr = tp / (tp + fn)   # Recall
fpr = fp / (fp + tn)
tnr = tn / (tn + fp)

print("\nRates:")
print("TPR (Recall):", tpr)
print("FPR        :", fpr)
print("TNR        :", tnr)

# ROC CURVE
fpr_curve, tpr_curve, thresholds = roc_curve(y_true, mse)
roc_auc = auc(fpr_curve, tpr_curve)

print("\nROC AUC:", roc_auc)

# Plot ROC
plt.figure()
plt.plot(fpr_curve, tpr_curve, label="ROC curve (area = %0.4f)" % roc_auc)
plt.plot([0, 1], [0, 1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - Autoencoder Anomaly Detection")
plt.legend(loc="lower right")
plt.show()
