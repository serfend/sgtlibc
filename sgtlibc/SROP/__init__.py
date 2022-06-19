from pwn import SigreturnFrame as baseSigreturnFrame


class SigreturnFrame(baseSigreturnFrame):
    def __init__(self):
        return super().__init__()

    @property
    def dump_to_bytes(self) -> bytes:
        return bytes(self)

    @property
    def dump_to_str(self) -> str:
        return str(self)

    @property
    def length(self):
        return len(self)


class SigreturnFrameX86(SigreturnFrame):
    def __init__(self):
        return super().__init__()

    @property
    def gs(self):
        return self.gs

    @property.setter
    def gs(self, value: int):
        self.gs = value

    @property
    def fs(self):
        return self.fs

    @property.setter
    def fs(self, value: int):
        self.fs = value

    ...  # 以下有n个类似的结构
