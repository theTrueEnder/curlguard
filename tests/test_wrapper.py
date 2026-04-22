import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from curlguard.wrapper import CurlWrapper


def test_wrapper_import():
    assert CurlWrapper is not None