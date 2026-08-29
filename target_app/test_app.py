from app import app


def test_normal_lookup_works():
    client = app.test_client()
    response = client.get("/user", query_string={"name": "alice"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    assert body["users"][0]["name"] == "alice"


def test_unknown_user_returns_empty():
    client = app.test_client()
    response = client.get("/user", query_string={"name": "nobody"})

    assert response.status_code == 200
    assert response.get_json()["count"] == 0
