import os
from clang import cindex
from src.utils.utils import get_logger

logger = get_logger(__name__)

def load_libclang():
    # load libclang shared library from environment variable
    try:
        p = os.environ.get("LIBCLANG_PATH")
        if p and os.path.isfile(p):
            cindex.Config.set_library_file(p)
            return
        else:
            logger.error("LIBCLANG_PATH environment variable is not set or points to an invalid file.")
    except Exception:
        logger.error("Failed to load libclang from LIBCLANG_PATH.")