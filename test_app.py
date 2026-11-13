from app import app

def test_health():
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"

def test_predict():
    client = app.test_client()
    response = client.post("/api/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json
    assert data["prediction"] in ["PHISHING", "LEGITIMATE"]
    assert 0 <= data["phishing_probability"] <= 100
