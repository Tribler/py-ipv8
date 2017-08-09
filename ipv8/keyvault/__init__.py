import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libnacl')))

libnacl = __import__("libnacl")
import libnacl
import libnacl.dual
import libnacl.encode
import libnacl.public
import libnacl.sign