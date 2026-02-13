class XBDMError(Exception):
    pass


class XBDMConnectionError(XBDMError):
    pass


class XBDMCommandError(XBDMError):
    def __init__(self, code, message):
        super().__init__(f"XBDM Error {code}: {message}")
        self.code = code
        self.message = message
