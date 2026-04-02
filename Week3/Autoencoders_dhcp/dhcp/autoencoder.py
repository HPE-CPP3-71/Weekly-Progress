import pandas as pd
import numpy as np
import joblib
import os

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_curve, auc
)

import tensorflow as tf
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model


# Config
DATA_FILE = "dhcp_flowmon_dataset.csv"
MODEL_PATH = "dhcp_autoencoder.keras"
BUNDLE_PATH = "dhcp_preprocessing.pkl"

EPOCHS = 25
BATCH_SIZE = 128


# Load data
def load_data():
    df = pd.read_csv(DATA_FILE)
    print("Dataset shape:", df.shape)
    return df


# Preprocess
def preprocess(df, bundle=None):

    df.columns = df.columns.str.lower().str.strip()

    y = df["label"].apply(lambda x: 0 if x == "BENIGN" else 1).values

    drop_cols = ["label", "attack_type", "packet_no", "src_mac"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    X = X.replace([np.inf, -np.inf], np.nan)

    num_cols = X.select_dtypes(include=[np.number]).columns
    X[num_cols] = X[num_cols].fillna(X[num_cols].median())

    cat_cols = X.select_dtypes(exclude=[np.number]).columns
    X[cat_cols] = X[cat_cols].fillna("missing")

    X = pd.get_dummies(X)

    if bundle is not None:
        scaler = bundle["scaler"]
        old_cols = bundle["columns"]

        missing_cols = list(set(old_cols) - set(X.columns))
        X = pd.concat(
            [X, pd.DataFrame(0, index=X.index, columns=missing_cols)],
            axis=1
        )

        X = X[old_cols]
        X_scaled = scaler.transform(X)

    else:
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)
        old_cols = X.columns.tolist()

    return X_scaled, y, scaler, old_cols


# Model
def build_autoencoder(input_dim):

    inp = Input(shape=(input_dim,))
    x = Dense(128, activation="relu")(inp)
    x = Dense(64, activation="relu")(x)
    x = Dense(32, activation="relu")(x)

    x = Dense(64, activation="relu")(x)
    x = Dense(128, activation="relu")(x)
    out = Dense(input_dim, activation="sigmoid")(x)

    model = Model(inp, out)
    model.compile(optimizer="adam", loss="mse")

    return model


# Main
def main():

    df = load_data()

    bundle = joblib.load(BUNDLE_PATH) if os.path.exists(BUNDLE_PATH) else None

    X, y, scaler, columns = preprocess(df, bundle)

    # Split
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    X_train = X_train_full[y_train_full == 0]

    X_train, X_val = train_test_split(
        X_train, test_size=0.2, random_state=42
    )

    print("\nTraining samples:", X_train.shape)
    print("Validation samples:", X_val.shape)
    print("Test samples:", X_test.shape)

    if os.path.exists(MODEL_PATH):
        model = tf.keras.models.load_model(MODEL_PATH)
        print("\nLoaded existing model")
    else:
        model = build_autoencoder(X_train.shape[1])
        print("\nCreated new model")

    model.fit(
        X_train, X_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_data=(X_val, X_val),
        verbose=1
    )

    model.save(MODEL_PATH)

    val_pred = model.predict(X_val, verbose=0)
    mse_val = np.mean((X_val - val_pred) ** 2, axis=1)

    threshold = np.percentile(mse_val, 95)

    print(f"\nThreshold selected: {threshold:.6f}")

    joblib.dump({
        "scaler": scaler,
        "columns": columns,
        "threshold": threshold
    }, BUNDLE_PATH)

    test_pred = model.predict(X_test, verbose=0)
    mse_test = np.mean((X_test - test_pred) ** 2, axis=1)

    y_pred = (mse_test > threshold).astype(int)

    print("\n=== DHCP ANOMALY DETECTION METRICS ===")

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nConfusion Matrix:")
    print(cm)

    tn, fp, fn, tp = cm.ravel()

    print("\nDetailed Breakdown:")
    print(f"TP: {tp}")
    print(f"TN: {tn}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")

    print("\nRates:")
    print(f"True Rate (Recall): {rec:.4f}")
    print(f"False Rate: {fp / (fp + tn):.4f}")

    fpr, tpr, thresholds = roc_curve(y_test, mse_test)
    roc_auc = auc(fpr, tpr)

    print(f"\nROC AUC Score: {roc_auc:.4f}")


if __name__ == "__main__":
    main()
