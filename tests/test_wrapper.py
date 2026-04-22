import pytest
from curlguard.wrapper import CurlWrapper


def test_wrapper_import():
    assert CurlWrapper is not None