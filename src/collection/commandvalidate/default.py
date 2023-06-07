class NoValidate:
    def __init__(self) -> None:
        pass
    def fetch(self) -> dict:
        return {}
    def verify(self, utterance, reply=None, delta=120, data=None):
        return True, {}, {}