"""
Quick script to apply an XOR key to a file

Author:
daniel@justbeck.com

Usage:
xor_file.py [-h] [--hex] xor_key filename
"""

import argparse

def XorFile(filename, xor_key):
	""" XORs a file and returns the contents """

	out = []
	i = 0

	for b in open(filename, 'rb').read():
		out.append(chr(ord(b) ^ ord(xor_key[i % len(xor_key)])))
		i += 1

	return ''.join(out)


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="XOR a file with a given key and write the output to a new file")
	parser.add_argument("--hex", help="Read the XOR key as a hex string", action="store_true")
	parser.add_argument("xor_key", help="The XOR key to use")
	parser.add_argument("filename", help="The path of the file to XOR")
	args = parser.parse_args()

	if args.hex:

		try:
			xor_key = args.xor_key.decode('hex')
		except TypeError:
			print "Error: XOR key cannot be converted from hex"
			exit()
	else:
		xor_key = args.xor_key


	output_data = XorFile(args.filename, xor_key)

	output_filename = args.filename + '.xor'

	open(output_filename, 'wb').write(output_data)

	print "XOR'd %s bytes. Saved file to:\n%s" % (len(output_data), output_filename)