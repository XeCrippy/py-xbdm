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
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 400
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)

class XBDMMaxConnectionsError(XBDMCommandError, code=401):
    """401 — max number of connections exceeded"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 401
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)

class XBDMFileNotFoundError(XBDMCommandError, code=402):
    """402 — file not found"""
    def __init__(self, path_or_code: Optional[int] = None, message: str = ""):
        if isinstance(path_or_code, str) and not message:
            self.path = path_or_code
            super().__init__(402, f"File not found: {path_or_code}")
        else:
            self.path = message
            super().__init__(path_or_code, message)

class XBDMNoSuchModuleError(XBDMCommandError, code=403):
    """403 — no such module"""
    def __init__(self, module_or_code: Optional[int] = None, message: str = ""):
        if isinstance(module_or_code, str) and not message:
            self.module = module_or_code
            super().__init__(403, f"No such module: {module_or_code}")
        else:
            self.module = message
            super().__init__(module_or_code, message)

class XBDMMemoryNotMappedError(XBDMCommandError, code=404):
    """404 — memory not mapped"""
    def __init__(self, address_or_code: Optional[int] = None, message: str = ""):
        if isinstance(address_or_code, str) and not message:
            self.address = address_or_code
            super().__init__(404, f"Memory not mapped: {address_or_code}")
        else:
            self.address = message
            super().__init__(address_or_code, message)

class XBDMNoSuchThreadError(XBDMCommandError, code=405):
    """405 — no such thread"""
    def __init__(self, thread_or_code: Optional[int] = None, message: str = ""):
        if isinstance(thread_or_code, str) and not message:
            self.thread = thread_or_code
            super().__init__(405, f"No such thread: {thread_or_code}")
        else:
            self.thread = message
            super().__init__(thread_or_code, message)

class XBDMSetSysTimeError(XBDMCommandError, code=406):
    """406 — setsystime failed"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 406
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)

class XBDMUnknownCommandError(XBDMCommandError, code=407):
    """407 — unknown command"""
    def __init__(self, command_or_code: Optional[int] = None, message: str = ""):
            if isinstance(command_or_code, str) and not message:
                self.command = command_or_code
                super().__init__(407, f"Unknown command: {command_or_code}")
            else:
                self.command = message
                super().__init__(command_or_code, message)

class XBDMNotStoppedError(XBDMCommandError, code=408):  
    """408 — not stopped"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 408
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)

class XBDMFileMustBeCopiedError(XBDMCommandError, code=409):
    """409 — file must be copied"""
    def __init__(self, path_or_code: Optional[int] = None, message: str = ""):
        if isinstance(path_or_code, str) and not message:
            self.path = path_or_code
            super().__init__(409, f"File must be copied: {path_or_code}")
        else:
            self.path = message
            super().__init__(path_or_code, message)

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
    def __init__(self, path_or_code: Optional[int] = None, message: str = ""):
        if isinstance(path_or_code, str) and not message:
            self.path = path_or_code
            super().__init__(411, f"Directory not empty: {path_or_code}")
        else:
            self.path = message
            super().__init__(path_or_code, message)

class XBDMFilenameInvalidError(XBDMCommandError, code=412):
    """412 — filename is invalid"""
    def __init__(self, filename_or_code: Optional[int] = None, message: str = ""):
        if isinstance(filename_or_code, str) and not message:
            self.filename = filename_or_code
            super().__init__(412, f"Filename is invalid: {filename_or_code}")
        else:
            self.filename = message
            super().__init__(filename_or_code, message)

class XBDMFileCannotBeCreatedError(XBDMCommandError, code=413):
    """413 — file cannot be created"""
    def __init__(self, path_or_code: Optional[int] = None, message: str = ""):
        if isinstance(path_or_code, str) and not message:
            self.path = path_or_code
            super().__init__(413, f"File cannot be created: {path_or_code}")
        else:
            self.path = message
            super().__init__(path_or_code, message)

class XBDMAccessDeniedError(XBDMCommandError, code=414):
    """414 — access denied"""
    def __init__(self, resource_or_code: Optional[int] = None, message: str = ""):
        if isinstance(resource_or_code, str) and not message:
            self.resource = resource_or_code
            super().__init__(414, f"Access denied: {resource_or_code}")
        else:
            self.resource = message
            super().__init__(resource_or_code, message)

class XBDMNoRoomOnDeviceError(XBDMCommandError, code=415):
    """415 — no room on device"""
    def __init__(self, resource_or_code: Optional[int] = None, message: str = ""):
        if isinstance(resource_or_code, str) and not message:
            self.resource = resource_or_code
            super().__init__(415, f"No room on device: {resource_or_code}")
        else:
            self.resource = message
            super().__init__(resource_or_code, message)

class XBDMNotDebuggableError(XBDMCommandError, code=416):
    """416 — not debuggable"""
    def __init__(self, resource_or_code: Optional[int] = None, message: str = ""):
            if isinstance(resource_or_code, str) and not message:
                self.resource = resource_or_code
                super().__init__(416, f"Not debuggable: {resource_or_code}")
            else:
                self.resource = message
                super().__init__(resource_or_code, message)

class XBDMTypeInvalidError(XBDMCommandError, code=417):
    """417 — type invalid"""
    def __init__(self, type_or_code: Optional[int] = None, message: str = ""):
        if isinstance(type_or_code, str) and not message:
            self.type = type_or_code
            super().__init__(417, f"Type invalid: {type_or_code}")
        else:
            self.type = message
            super().__init__(type_or_code, message)

class XBDMDataNotAvailableError(XBDMCommandError, code=418):
    """418 — data not available"""
    def __init__(self, data_or_code: Optional[int] = None, message: str = ""):
        if isinstance(data_or_code, str) and not message:
            self.data = data_or_code
            super().__init__(418, f"Data not available: {data_or_code}")
        else:
            self.data = message
            super().__init__(data_or_code, message)

class XBDMBoxNotLockedError(XBDMCommandError, code=420):
    """420 — box not locked"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
            if isinstance(code_or_message, str) and not message:
                message = code_or_message
                code_or_message = 420
                super().__init__(code_or_message, message)
            else:
                super().__init__(code_or_message, message)

class XBDMKeyExchangeRequiredError(XBDMCommandError, code=421):
    """421 — key exchange required"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 421
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)

class XBDMDedicatedConnectionRequiredError(XBDMCommandError, code=422):
    """422 — dedicated connection required"""
    def __init__(self, code_or_message: Optional[int] = None, message: str = ""):
        if isinstance(code_or_message, str) and not message:
            message = code_or_message
            code_or_message = 422
            super().__init__(code_or_message, message)
        else:
            super().__init__(code_or_message, message)
