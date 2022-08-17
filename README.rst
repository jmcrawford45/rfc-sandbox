# rfc_sandbox

.. image:: https://readthedocs.org/projects/rfc-sandbox/badge/?version=latest
	:target: https://rfc-sandbox.readthedocs.io/en/latest/?badge=latest
	:alt: Documentation Status

.. image:: https://coveralls.io/repos/github/jmcrawford45/rfc_sandbox/badge.svg?branch=main
	:target: https://coveralls.io/github/jmcrawford45/rfc_sandbox?branch=main


Sandbox repo for me to learn through implementing RFCs of interest

Future work:
maintain protection, ownership, and (optional) mtime attributes for unzipped file
use streams instead of str for decompress out and compress in
don't re-init ByteIO in BitStream.write
dynamic huffman
use more than 1 block
encoding lookback > 1