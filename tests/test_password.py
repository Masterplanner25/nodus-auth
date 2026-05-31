from nodus_auth import hash_password, verify_password


def test_hash_is_not_plaintext():
    h = hash_password("secret")
    assert h != "secret"
    assert h.startswith("$2b$")


def test_verify_correct_password():
    h = hash_password("correct-horse")
    assert verify_password("correct-horse", h) is True


def test_verify_wrong_password():
    h = hash_password("correct-horse")
    assert verify_password("wrong-horse", h) is False


def test_different_hashes_for_same_password():
    h1 = hash_password("same")
    h2 = hash_password("same")
    # bcrypt uses a random salt
    assert h1 != h2
    assert verify_password("same", h1) is True
    assert verify_password("same", h2) is True
