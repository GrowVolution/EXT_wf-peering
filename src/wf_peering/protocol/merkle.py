import hashlib

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> str:
    return _h(b"\x00" + data).hex()


def node_hash(left: str, right: str) -> str:
    return _h(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hex()


def _split(n: int) -> int:
    k = 1
    while k << 1 < n: k <<= 1
    return k


def root(leaves: list[str]) -> str:
    if not leaves: return EMPTY_ROOT
    return _root(leaves, 0, len(leaves), {})


def _root(leaves: list[str], start: int, end: int, cache: dict) -> str:
    n = end - start
    if n == 1: return leaves[start]
    key = (start, end)
    if key in cache: return cache[key]
    k = _split(n)
    value = node_hash(_root(leaves, start, start + k, cache), _root(leaves, start + k, end, cache))
    cache[key] = value
    return value


def inclusion_proof(index: int, leaves: list[str]) -> list[str]:
    if not 0 <= index < len(leaves):
        raise ValueError("Leaf index is outside of the tree.")
    cache = {}

    def path(m: int, start: int, end: int) -> list[str]:
        n = end - start
        if n == 1: return []
        k = _split(n)
        if m < k:
            return path(m, start, start + k) + [_root(leaves, start + k, end, cache)]
        return path(m - k, start + k, end) + [_root(leaves, start, start + k, cache)]

    return path(index, 0, len(leaves))


def verify_inclusion(index: int, size: int, leaf: str, proof: list[str], expected_root: str) -> bool:
    if not 0 <= index < size: return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def consistency_proof(first: int, leaves: list[str]) -> list[str]:
    second = len(leaves)
    if not 0 < first <= second:
        raise ValueError("Consistency proofs need 0 < first <= second.")
    cache = {}

    def subproof(m: int, start: int, end: int, complete: bool) -> list[str]:
        n = end - start
        if m == n:
            return [] if complete else [_root(leaves, start, end, cache)]
        k = _split(n)
        if m <= k:
            return subproof(m, start, start + k, complete) + [_root(leaves, start + k, end, cache)]
        return subproof(m - k, start + k, end, False) + [_root(leaves, start, start + k, cache)]

    return subproof(first, 0, second, True)


def verify_consistency(first: int, second: int, first_root: str, second_root: str, proof: list[str]) -> bool:
    if first == second: return not proof and first_root == second_root
    if not 0 < first < second or not proof: return False
    if first & (first - 1) == 0:
        proof = [first_root] + list(proof)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
