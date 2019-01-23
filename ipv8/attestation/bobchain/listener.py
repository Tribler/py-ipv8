from pyipv8.ipv8.attestation.trustchain.listener import BlockListener

from .block import BobChainBlock

class BoBListener(BlockListener):

	BLOCK_CLASS = BobChainBlock

	def should_sign(self, block):
		return True

	def received_block(self, block):
		print "Received block %s.........................." % block