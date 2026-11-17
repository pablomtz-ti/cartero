import pytest

from cartero.knowledge import Knowledge


@pytest.fixture(scope="session")
def kb(tmp_path_factory) -> Knowledge:
    # user_dir vacío: los tests no dependen de listas descargadas en la máquina
    return Knowledge(user_dir=tmp_path_factory.mktemp("cartero-user"))
