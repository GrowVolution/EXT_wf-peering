

class CanonicalError(ValueError):
    pass


class IntegrityRecordError(ValueError):
    pass


class PolicyError(ValueError):
    pass


class LedgerError(Exception):
    def __init__(self, code: str, detail: dict | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail or {}


class CheckError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail
