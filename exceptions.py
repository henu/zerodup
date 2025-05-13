class CorruptedData(Exception):
    pass


class FatalError(Exception):
    def __init__(self, msg):
        super().__init__(msg)
