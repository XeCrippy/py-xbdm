from .exceptions import XBDMCommandError


class XBDMResponse:
    def __init__(self, code, message):
        self.code = code
        self.message = message

    @property
    def ok(self):
        return 200 <= self.code < 300


def parse_response_line(line: bytes, overide: bool = False) -> XBDMResponse:
    text = line.decode("ascii", errors="ignore").strip()

    # Example: "200- OK"
    code = int(text[:3])
    message = text[4:]

    if code >= 400 and not overide:
        raise XBDMCommandError.from_code(code, message)

    return XBDMResponse(code, message)
