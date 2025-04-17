class VulnCheck:
    def __init__(self, scanner):
        self.scanner = scanner

    def run(self):
        raise NotImplementedError("Each check must implement its own run() method.")
