# PhishGuard AI: AI-Based Phishing Website Detection System

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Install dependencies:
   `pip install -r requirements.txt`
4. (Optional) Retrain and compare the three classifiers:
   `python train_models.py`
5. Start the web app:
   `python app.py`
6. Open http://127.0.0.1:5000

## Machine-learning pipeline
The supplied `phishing.csv` contains 30 engineered website-security features and a `class` target.
The training script creates:
- Logistic Regression
- Random Forest
- Gradient Boosting

A stratified 80/20 train/test split is used with random_state=42. Accuracy, precision, recall and F1 are recorded in `models/model_comparison.json`. The highest-accuracy model is saved as `models/best_model.joblib` and is used for live URL prediction.

Dataset labels: `-1 = phishing`, `1 = legitimate`.

## Current trained comparison
The included trained artifacts were produced from the supplied dataset. Run `python train_models.py` to reproduce the comparison.

## API
`POST /api/check` with JSON `{ "url": "https://example.com" }` returns the prediction and probability.
`GET /api/models` returns the model comparison and selected best model.

## Safety
The URL extractor is designed to operate on URL/domain-level indicators without requiring the submitted page to be trusted. The optional page fetch is limited by a short timeout and should be sandboxed for public deployment. Do not allow unrestricted access to internal/private networks.
