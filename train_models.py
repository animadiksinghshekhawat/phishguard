"""Train and compare LR, RF and GB phishing classifiers.

The live application uses the highest-accuracy model saved as models/best_model.joblib.
"""
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE = Path(__file__).resolve().parent
MODEL_DIR = BASE / "models"
MODEL_DIR.mkdir(exist_ok=True)

FEATURES = [
    "UsingIP","LongURL","ShortURL","Symbol@","Redirecting//","PrefixSuffix-",
    "SubDomains","HTTPS","DomainRegLen","Favicon","NonStdPort","HTTPSDomainURL",
    "RequestURL","AnchorURL","LinksInScriptTags","ServerFormHandler","InfoEmail",
    "AbnormalURL","WebsiteForwarding","StatusBarCust","DisableRightClick",
    "UsingPopupWindow","IframeRedirection","AgeofDomain","DNSRecording",
    "WebsiteTraffic","PageRank","GoogleIndex","LinksPointingToPage","StatsReport"
]

# Dataset convention: -1 = phishing, +1 = legitimate.
PHISHING_LABEL = -1
LEGITIMATE_LABEL = 1


def main():
    df = pd.read_csv(BASE / "phishing.csv")
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"Missing dataset features: {missing}")

    X = df[FEATURES].astype(float)
    y = df["class"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=2500, random_state=42))
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=400,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.05,
            max_depth=3,
            random_state=42
        )
    }

    results = {}
    fitted = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        proba = model.predict_proba(X_test)
        classes = list(model.classes_)
        phishing_idx = classes.index(PHISHING_LABEL)
        phishing_proba = proba[:, phishing_idx]
        y_test_phishing = (y_test == PHISHING_LABEL).astype(int)
        roc_auc = roc_auc_score(y_test_phishing, phishing_proba)
        cm = confusion_matrix(y_test, pred, labels=[PHISHING_LABEL, LEGITIMATE_LABEL])
        results[name] = {
            "accuracy": round(float(accuracy_score(y_test, pred)), 6),
            "precision": round(float(precision_score(y_test, pred, pos_label=PHISHING_LABEL)), 6),
            "recall": round(float(recall_score(y_test, pred, pos_label=PHISHING_LABEL)), 6),
            "f1": round(float(f1_score(y_test, pred, pos_label=PHISHING_LABEL)), 6),
            "roc_auc": round(float(roc_auc), 6),
            "confusion_matrix": cm.tolist(),
            "test_samples": int(len(y_test))
        }
        fitted[name] = model

        filename = {
            "Logistic Regression": "logistic_regression.joblib",
            "Random Forest": "random_forest.joblib",
            "Gradient Boosting": "gradient_boosting.joblib"
        }[name]
        joblib.dump(model, MODEL_DIR / filename)

    best_name = max(results, key=lambda k: results[k]["accuracy"])
    best_model = fitted[best_name]
    joblib.dump(best_model, MODEL_DIR / "best_model.joblib")

    metadata = {
        "features": FEATURES,
        "target": "class",
        "mapping": {"-1": "phishing", "1": "legitimate"},
        "phishing_label": PHISHING_LABEL,
        "legitimate_label": LEGITIMATE_LABEL,
        "test_size": 0.20,
        "random_state": 42,
        "best_model": best_name,
        "results": results,
        "dataset_rows": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test))
    }
    (MODEL_DIR / "model_comparison.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (MODEL_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Model comparison:")
    for name, r in results.items():
        print(f"  {name}: Accuracy {r['accuracy']*100:.2f}% | Precision {r['precision']:.4f} | Recall {r['recall']:.4f} | F1 {r['f1']:.4f} | ROC-AUC {r['roc_auc']:.4f}")
    print(f"Best model: {best_name}")


if __name__ == "__main__":
    main()
