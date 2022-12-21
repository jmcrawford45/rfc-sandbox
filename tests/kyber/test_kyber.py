from kyber import *

def test_smod():
    assert smod(3325, FIELD_SIZE) == -4
    assert smod(-3320, FIELD_SIZE) == 9

def test_sample_uniform():
    assert sample_uniform(shake_128(''))[:4] == (3199, 697, 2212, 2302)
    assert sample_uniform(shake_128(''))[-3:] == (255, 846, 1)

def test_octect_to_bits():
    assert octets_to_bits(12,45) == (0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0)