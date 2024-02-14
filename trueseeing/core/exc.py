from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

class FatalError(Exception):
    pass

class InvalidSchemaError(Exception):
    pass

class InvalidContextError(Exception):
    pass

class InvalidFileFormatError(Exception):
    pass

class InvalidConfigKeyError(Exception):
    pass
