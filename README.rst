# rfc_sandbox

.. image:: https://readthedocs.org/projects/rfc-sandbox/badge/?version=latest
	:target: https://rfc-sandbox.readthedocs.io/en/latest/?badge=latest
	:alt: Documentation Status

.. image:: https://coveralls.io/repos/github/jmcrawford45/rfc_sandbox/badge.svg?branch=main
	:target: https://coveralls.io/github/jmcrawford45/rfc_sandbox?branch=main


Sandbox repo for me to learn through implementing RFCs of interest

Future work:
ux
	cli wrapper that operates on files
	use streams instead of str for decompress out and compress in
perf
	don't re-init ByteIO in BitStream.write
	dynamic huffman
	use more than 1 block
rtb
	clean mypy run