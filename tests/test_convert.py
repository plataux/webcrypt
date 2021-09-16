

import webcrypt.convert as conv
import pytest
from random import choice
import os

from math import nan


@pytest.mark.parametrize(
    "num",
    [0, 51231986123871638713875481283751283,
     *[choice(range(4343258345843688645)) for _ in range(100)]]
)
def test_int_bytes(num):
    b = conv.int_to_bytes(num)
    num2 = conv.int_from_bytes(b)
    assert num == num2


@pytest.mark.parametrize(
    "num",
    [None, "128", 1024.0, 3j + 4, b'256', nan, -10220322323032432423420234234]
)
def test_fail_int_bytes(num):

    with pytest.raises(Exception):
        b = conv.int_to_bytes(num)
        num2 = conv.int_from_bytes(b)
        assert num == num2


@pytest.mark.parametrize(
    "num",
    [0, 512319861238716387138754812837512834545434534543,
     *[choice(range(4343258345843688645)) for _ in range(100)]]
)
def test_int_b64(num):
    b64 = conv.int_to_b64(num)
    num2 = conv.int_from_b64(b64)
    assert num == num2


def test_bytes_base64():
    for x in range(100):
        bt = os.urandom(choice(range(1024 * 512)))

        pad = choice((True, False))

        bt_b64 = conv.bytes_to_b64(bt, pad)

        bt2 = conv.bytes_from_b64(bt_b64, pad)

        assert bt == bt2