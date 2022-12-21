from bloom_filter import BloomFilter


def test_filter_basic():
    bloom = BloomFilter()
    for i in range(100):
        if i % 2 == 0:
            bloom.add(str(i).encode())
    assert not bloom.contains(b"1")
    assert bloom.contains(b"2")
