"""Independent bounded reader for this corpus's BEEF-v1/Atomic-BEEF bytes.

Only its advertised one-leaf synthetic block proofs are accepted here. This is
not a general BEEF SDK. Unknown formats/proof layouts are unsupported, never
silently treated as verified.
"""

from bitcoinx import Tx


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, size):
        assert size >= 0 and self.pos + size <= len(self.data), "truncated BEEF"
        out = self.data[self.pos : self.pos + size]
        self.pos += size
        return out

    def uint(self, size):
        return int.from_bytes(self.read(size), "little")

    def varint(self):
        n = self.uint(1)
        if n < 253:
            return n
        size = {253: 2, 254: 4, 255: 8}[n]
        value = self.uint(size)
        assert (
            value >= {2: 253, 4: 65536, 8: 4294967296}[size]
        ), "nonminimal CompactSize"
        assert value <= 1048576, "corpus allocation bound"
        return value


def parse_beef(data, expected=None, roots=None):
    r = Reader(data)
    version = r.uint(4)
    target = None
    if version == 0x01010101:
        target = r.read(32)[::-1].hex()
        version = r.uint(4)
    assert version == 0xEFBE0001, "only pinned BEEF-v1 in this corpus"
    if expected is not None and target is not None:
        assert target == expected, "wrong Atomic target"
    bumps = []
    for _ in range(r.varint()):
        height = r.varint()
        assert r.uint(1) == 1, "unsupported synthetic proof depth"
        assert r.varint() == 1 and r.varint() == 0, "unsupported synthetic proof leaves"
        assert r.uint(1) == 2, "required txid leaf flag"
        root = r.read(32)[::-1].hex()
        bumps.append((height, root))
    txs = {}
    placements = {}
    for _ in range(r.varint()):
        start = r.pos
        tx = Tx.read(r.read)
        txid = tx.hex_hash()
        assert txid not in txs
        assert tx.to_bytes() == data[start : r.pos]
        txs[txid] = tx
        flag = r.uint(1)
        assert flag in (0, 1)
        if flag:
            index = r.varint()
            assert index < len(bumps)
            height, root = bumps[index]
            assert root == txid
            if roots is not None:
                assert (height, root) in roots, "unselected block root"
            placements[txid] = (height, root)
    assert r.pos == len(data), "trailing BEEF"
    if expected is not None:
        assert expected in txs, "target missing raw bytes"
    if target is not None:
        assert target in txs
    return txs, placements
