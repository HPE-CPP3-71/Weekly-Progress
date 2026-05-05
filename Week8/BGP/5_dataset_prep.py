import os
import pandas as pd
from sklearn.utils import resample
from sklearn.model_selection import train_test_split

PROC_DIR = "data/processed"

FEATURE_COLS = [
    "num_announcements",
    "num_withdrawals",
    "avg_as_path_length",
    "max_as_path_length",
    "std_as_path_length",
    "duplicate_withdrawals",
    "unique_withdrawn_prefixes",
    "total_records",
]


def prepare_dataset():
    path = os.path.join(PROC_DIR, "labelled_dataset.csv")
    df = pd.read_csv(path)

    # Use MAD label
    df = df[FEATURE_COLS + ["mad_label"]].dropna()

    print("Original distribution:")
    print(df["mad_label"].value_counts())

    X = df[FEATURE_COLS]
    y = df["mad_label"]

    # ─────────────────────────────
    # SPLIT FIRST (IMPORTANT)
    # ─────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Convert to DataFrame for resampling
    train_df = X_train.copy()
    train_df["label"] = y_train.values

    df_maj = train_df[train_df["label"] == 0]
    df_min = train_df[train_df["label"] == 1]

    print("\nBefore balancing (train only):")
    print(train_df["label"].value_counts())

    # ─────────────────────────────
    # OVERSAMPLE TRAIN ONLY
    # ─────────────────────────────
    df_min_up = resample(
        df_min,
        replace=True,
        n_samples=len(df_maj),
        random_state=42
    )

    train_bal = pd.concat([df_maj, df_min_up]).sample(frac=1, random_state=42)

    X_train = train_bal[FEATURE_COLS].values
    y_train = train_bal["label"].values

    X_test = X_test.values
    y_test = y_test.values

    print("\nAfter balancing:")
    print(pd.Series(y_train).value_counts())

    # Save
    pd.DataFrame(X_train, columns=FEATURE_COLS).assign(label=y_train)\
        .to_csv(os.path.join(PROC_DIR, "train.csv"), index=False)

    pd.DataFrame(X_test, columns=FEATURE_COLS).assign(label=y_test)\
        .to_csv(os.path.join(PROC_DIR, "test.csv"), index=False)

    print("\nSaved train.csv and test.csv")

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    prepare_dataset()