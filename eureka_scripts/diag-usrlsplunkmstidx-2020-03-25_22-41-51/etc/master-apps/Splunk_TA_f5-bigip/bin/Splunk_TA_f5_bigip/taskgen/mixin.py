class KeyCompMixin:
    def __eq__(self, other):
        self.assert_type(other)
        return self.compare_key() == other.compare_key()

    def __ne__(self, other):
        self.assert_type(other)
        return self.compare_key() != other.compare_key()

    def __lt__(self, other):
        self.assert_type(other)
        return self.compare_key() < other.compare_key()

    def __le__(self, other):
        self.assert_type(other)
        return self.compare_key() <= other.compare_key()

    def __gt__(self, other):
        self.assert_type(other)
        return self.compare_key() > other.compare_key()

    def __ge__(self, other):
        self.assert_type(other)
        return self.compare_key() >= other.compare_key()

class KeyHashMixin:
    def __hash__(self):
        return hash(self.compare_key())