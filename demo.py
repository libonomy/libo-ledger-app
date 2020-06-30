from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct

def parse_bip32_path(path):
	if len(path) == 0:
		return ""
	result = ""
	elements = path.split('/')
	for pathElement in elements:
		element = pathElement.split('\'')
		if len(element) == 1:
			result = result + struct.pack(">I", int(element[0]))			
		else:
			result = result + struct.pack(">I", 0x80000000 | int(element[0]))
	return result

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to sign with")
parser.add_argument('--tx', help="TX to sign, hex encoded")
args = parser.parse_args()

if args.path == None:
	args.path="44'/5519'/0'/0'/0'"

donglePath = parse_bip32_path(args.path)

pathLength = len(donglePath) + 1
p1 = "80"
p2 = "80"
data1 = ("0a120a0b0899cf80e80510b88be609120318e9071202180318a08d062202081e320f48617264776172653157616c6c657472180a160a090a0318e90710a79a010a090a0318f20710a89a01").decode('hex')
apdu = ("e002" + p1 + p2).decode('hex') + chr(pathLength) + chr(len(donglePath) / 4) + donglePath

dongle = getDongle(True)
result = dongle.exchange(bytes(apdu))