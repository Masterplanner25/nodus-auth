from nodus_auth import generate_key, hash_key


def test_hash_key_is_deterministic():
    assert hash_key("abc") == hash_key("abc")


def test_hash_key_differs_for_different_inputs():
    assert hash_key("abc") != hash_key("xyz")


def test_hash_key_is_hex_64_chars():
    h = hash_key("test")
    assert len(h) == 64
    int(h, 16)  # must be valid hex


def test_generate_key_returns_tuple():
    raw, hashed = generate_key()
    assert isinstance(raw, str)
    assert isinstance(hashed, str)


def test_generate_key_hash_matches_raw():
    raw, hashed = generate_key()
    assert hash_key(raw) == hashed


def test_generate_key_default_prefix():
    raw, _ = generate_key()
    assert raw.startswith("nodus_")


def test_generate_key_custom_prefix():
    raw, _ = generate_key(prefix="myapp_")
    assert raw.startswith("myapp_")


def test_generate_key_unique():
    raw1, _ = generate_key()
    raw2, _ = generate_key()
    assert raw1 != raw2
