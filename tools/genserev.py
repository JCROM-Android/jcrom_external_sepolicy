#!/usr/bin/env python

import os
import sys
import hashlib
from optparse import OptionParser

__VERSION = (0, 2)

def main():

	usage  = "This tool generates a revision file that maps a sha256 value and file name to a revision for the policy files\n"

	version = "%prog " + str(__VERSION)

	parser = OptionParser(usage=usage, version=version)

	parser.add_option("-o", "--output", default="stdout", dest="output_file",
		              metavar="FILE", help="Specify an output file, default is stdout")

	parser.add_option("-r", "--revision", default="NONE", dest="revision",
		              metavar="REVISION", help="Specify a revision for this policy")

	(options, args) = parser.parse_args()

	output_file = sys.stdout if options.output_file == "stdout" else open(options.output_file, "w")

	output_file.write(options.revision + '\n')

	for f in args:

		name = os.path.basename(f)
		m = hashlib.sha256()
		m.update(open(f, "r").read())
		hexd = m.hexdigest()
		output_file.write(name + '\t' + hexd + '\n')

if __name__ == "__main__":
	main()
