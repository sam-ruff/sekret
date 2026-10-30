import atexit
import os
import shutil
import tempfile
from pathlib import Path

from ansible.utils.collection_loader._collection_finder import _AnsibleCollectionFinder

COLLECTION_DIR = Path(__file__).resolve().parent.parent


def _collections_root() -> str:
    root = Path(tempfile.mkdtemp(prefix="sekret-ansible-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    namespace = root / "ansible_collections" / "sekret"
    namespace.mkdir(parents=True)
    os.symlink(COLLECTION_DIR, namespace / "secrets")
    return str(root)


COLLECTIONS_ROOT = _collections_root()
_AnsibleCollectionFinder(paths=[COLLECTIONS_ROOT])._install()
