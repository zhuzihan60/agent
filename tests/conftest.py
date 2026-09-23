"""Classify tests that use the protected disk cache fixture before -m filtering."""

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if {'cache_root', 'protected_state'} & set(item.fixturenames):
            item.add_marker(pytest.mark.privileged_linux)
