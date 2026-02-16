"""
200- OK
Standard response for successful execution of a command.
201- connected
Initial response sent after a connection is established. The client does not need to send anything to solicit this response.
202- multiline response follows
The response line is followed by one or more additional lines of data terminated by a line containing only a . (period). The client must read all available lines before sending another command.
203- binary response follows
The response line is followed by raw binary data, the length of which is indicated in some command-specific way. The client must read all available data before sending another command.
204- send binary data
The command is expecting additional binary data from the client. After the client sends the required number of bytes, XBDM will send another response line with the final result of the command.
205- connection dedicated
The connection has been moved to a dedicated handler thread (see #Connection dedication).
"""



from typing import Dict, Optional, Type


class XBDMError(Exception):
    pass


class XBDMConnectionError(XBDMError):
    pass


class XBDMCommandError(XBDMError):
    """Base class for all XBDM command errors.

    Subclasses register themselves via ``code`` so the factory
    ``XBDMCommandError.from_code()`` returns the right type.
    """
    code: Optional[int] = None
    _registry: Dict[int, Type["XBDMCommandError"]] = {}

    def __init_subclass__(cls, code: Optional[int] = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if code is not None:
            cls.code = code
            XBDMCommandError._registry[code] = cls

    def __init__(self, code: Optional[int] = None, message: str = ""):
        if isinstance(code, str):
            message = code
            code = self.__class__.code or 0
        super().__init__(f"XBDM Error {code}: {message}")
        self.code = code
        self.message = message

    @classmethod
    def from_code(cls, code: int, message: str = "") -> "XBDMCommandError":
        """Return the specific exception subclass for *code*, or the base class."""
        exc_cls = cls._registry.get(code, cls)
        return exc_cls(code, message)


# ── 4xx errors ────────────────────────────────

class XBDMUnexpectedError(XBDMCommandError, code=400):
    """400 — unexpected error"""

class XBDMMaxConnectionsError(XBDMCommandError, code=401):
    """401 — max number of connections exceeded"""

class XBDMFileNotFoundError(XBDMCommandError, code=402):
    """402 — file not found"""

class XBDMNoSuchModuleError(XBDMCommandError, code=403):
    """403 — no such module"""

class XBDMMemoryNotMappedError(XBDMCommandError, code=404):
    """404 — memory not mapped"""

class XBDMNoSuchThreadError(XBDMCommandError, code=405):
    """405 — no such thread"""

class XBDMSetSysTimeError(XBDMCommandError, code=406):
    """406 — setsystime failed"""

class XBDMUnknownCommandError(XBDMCommandError, code=407):
    """407 — unknown command"""

class XBDMNotStoppedError(XBDMCommandError, code=408):
    """408 — not stopped"""

class XBDMFileMustBeCopiedError(XBDMCommandError, code=409):
    """409 — file must be copied"""

class XBDMFileAlreadyExistsError(XBDMCommandError, code=410):
    """410 — file already exists"""
    def __init__(self, path_or_code: Optional[int] = None, message: str = ""):
        if isinstance(path_or_code, str) and not message:
            self.path = path_or_code
            super().__init__(410, f"File already exists: {path_or_code}")
        else:
            self.path = message
            super().__init__(path_or_code, message)

class XBDMDirectoryNotEmptyError(XBDMCommandError, code=411):
    """411 — directory not empty"""

class XBDMFilenameInvalidError(XBDMCommandError, code=412):
    """412 — filename is invalid"""

class XBDMFileCannotBeCreatedError(XBDMCommandError, code=413):
    """413 — file cannot be created"""

class XBDMAccessDeniedError(XBDMCommandError, code=414):
    """414 — access denied"""

class XBDMNoRoomOnDeviceError(XBDMCommandError, code=415):
    """415 — no room on device"""

class XBDMNotDebuggableError(XBDMCommandError, code=416):
    """416 — not debuggable"""

class XBDMTypeInvalidError(XBDMCommandError, code=417):
    """417 — type invalid"""

class XBDMDataNotAvailableError(XBDMCommandError, code=418):
    """418 — data not available"""

class XBDMBoxNotLockedError(XBDMCommandError, code=420):
    """420 — box not locked"""

class XBDMKeyExchangeRequiredError(XBDMCommandError, code=421):
    """421 — key exchange required"""

class XBDMDedicatedConnectionRequiredError(XBDMCommandError, code=422):
    """422 — dedicated connection required"""
