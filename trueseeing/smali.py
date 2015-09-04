import re

class Package:
    def __init__(self, apk):
        self.apk = apk

    def disassembled(self):
        return PackageAnalysis(PackageContent(self.apk).unpacked()).analyzed()

class PackageAnalysis:
    res = None
    smali = None
    unknown = None
    lib = None

    def __init__(self, path):
        self.path = path

    def analyzed(self):
        self.res = []
        self.smali = []
        self.unknown = []
        self.lib = []

class PackageContent:
    def __init__(self, apk):
        self.apk = apk

    def unpacked(self):
        return '/tmp/package/unpacked'

class Directory:
    def __init__(self, path):
        self.path = path

    def remove(self):
        os.path.rmtree(self.path)

    def __enter__(self):
        return self

    def __exit__(self, exc_code, exc_value, traceback):
        self.remove()

class Smali:
    def __init__(self, source_code_string_in_smali):
        self.code = source_code_string_in_smali

class Insn:
    op = None
    l = None
    r = None

    def __init__(self, mnemonic):
        ops = self.analyzed(mnemonic)
        self.op = ops[0]
        try:
            self.l = ops[1]
        except IndexError:
            pass
        try:
            self.r = ops[2:]
        except IndexError:
            pass

    @staticmethod
    def analyzed(mnemonic):
        return [m.group(0) for m in re.finditer(r'[:.][a-z0-9_-]+|".*"|[vp][0-9]+|{[vp0-9,. ]+}|[a-z0-9/-]+|[A-Za-z_0-9/;$()<>-]+', mnemonic)]

    def __repr__(self):
        return '%s:%s:%s' % (self.op, self.l, self.r)

if __name__ == '__main__':
    Package(apk).disassembled().of('filename.smali')
