
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer

# Demonstration dataset with illustrative labels.
# These labels are rules for a classroom demo, not verified attacks.
def main():
    df = pd.read_csv("data/security_logs.csv")

    suspicious_types = [
        "Failed Login",
        "Port Scan",
        "Malware Alert",
        "Suspicious File"
    ]

    df["label"] = df["event_type"].isin(suspicious_types).astype(int)

    features = ["event_type"]
    X = df[features]
    y = df["label"]

    # A single-class dataset cannot train a useful classifier.
    if y.nunique() < 2:
        print("The dataset needs both normal and suspicious examples.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    preprocess = ColumnTransformer([
        ("event", OneHotEncoder(handle_unknown="ignore"), features)
    ])

    model = make_pipeline(
        preprocess,
        RandomForestClassifier(n_estimators=100, random_state=42)
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("===== ML INTRUSION DETECTION DEMO =====")
    print("0 = Normal | 1 = Potentially suspicious")
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, predictions))
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, zero_division=0,
        target_names=["Normal", "Potentially suspicious"]
    ))

    results = X_test.copy()
    results["actual_label"] = y_test
    results["predicted_label"] = predictions
    print("\nSample predictions:")
    print(results.head(10).to_string(index=False))

    print("\nNote: Labels are derived from event type for demonstration.")
    print("This does not establish real-world attack detection accuracy.")

if __name__ == "__main__":
    main()
