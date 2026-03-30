"""
Tests for the HashAxe core normalization engine.
"""

from hashaxe.core.normalization import normalize_hash_string, normalize_bytes_payload

def test_normalize_hash_string_clean():
    res = normalize_hash_string("d41d8cd98f00b204e9800998ecf8427e")
    assert res.clean_hash == "d41d8cd98f00b204e9800998ecf8427e"
    assert not res.is_modified
    assert res.context == "raw"

def test_normalize_hash_string_quotes():
    res = normalize_hash_string('"d41d8cd98f00b204e9800998ecf8427e"')
    assert res.clean_hash == "d41d8cd98f00b204e9800998ecf8427e"
    assert res.is_modified

def test_normalize_hash_string_shadow():
    res = normalize_hash_string("root:$6$salt$hash:18742:0:99999:7:::")
    assert res.clean_hash == "$6$salt$hash"
    assert res.is_modified
    assert res.context == "shadow_file"

def test_normalize_hash_string_windows_hashdump():
    res = normalize_hash_string("Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")
    assert res.clean_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert res.is_modified
    assert res.context == "hashdump"

def test_normalize_hash_string_shell_artifacts():
    res = normalize_hash_string("d41d8cd98f00b204e9800998ecf8427e < /dev/null")
    assert res.clean_hash == "d41d8cd98f00b204e9800998ecf8427e"
    assert res.is_modified

def test_normalize_bytes_payload():
    assert normalize_bytes_payload(b"hello\\r\\nworld") == b"hello\\nworld"
    assert normalize_bytes_payload(b"hello\\rworld") == b"hello\\nworld"
    assert normalize_bytes_payload(b"hello\\nworld") == b"hello\\nworld"
