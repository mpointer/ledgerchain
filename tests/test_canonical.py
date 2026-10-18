from __future__ import annotations

import pytest

from ledgerchain import CanonicalizationError, canonicalize, sha256_hex


def test_key_order_does_not_change_bytes():
    assert canonicalize({"b": 1, "a": 2}) == canonicalize({"a": 2, "b": 1})
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_no_whitespace_and_utf8():
    assert canonicalize({"k": "é", "n": [1, 2]}) == '{"k":"é","n":[1,2]}'.encode()


def test_numbers_use_shortest_round_trip_form():
    # RFC 8785 appendix examples: integral floats print without a fraction,
    # and exponents use ECMAScript form.
    assert canonicalize(1.0) == b"1"
    assert canonicalize(1e21) == b"1e+21"
    assert canonicalize(0.000001) == b"0.000001"


def test_sha256_hex_is_64_lowercase_hex():
    digest = sha256_hex({"x": 1})
    assert len(digest) == 64
    assert digest == digest.lower()
    assert int(digest, 16) >= 0


def test_sha256_hex_matches_known_vector():
    # sha256 of the bytes b'{}'
    assert sha256_hex({}) == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_unserializable_values_raise():
    with pytest.raises(CanonicalizationError):
        canonicalize({1, 2, 3})
