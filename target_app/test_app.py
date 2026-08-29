from app import user


def test_app_imports():
    assert callable(user)


def test_normal_lookup_works():
    response = user()
    assert response == "USER RESULT"
