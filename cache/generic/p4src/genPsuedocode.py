# autogen stateful function psuedocode

def main():
	svCount = 4
	print ("// short vecs")
	genShortVecs(svCount)

	lvCount = 23
	print ("// long vecs inline code")
	genLongVecsInline(lvCount)
	print ("// long vecs")
	genLongVecs(lvCount)

def genShortVecs(svCount):
	for i in range(svCount):
		svRW = """
action sRWShortVec_%s() {
	idx = sfMeta.hashVal;
	sfShortVector.w%s = rShortVec_%s[idx];
	rShortVec_%s[idx] = currentPfVec.w0;
}
	"""%(i, i, i, i)
		svR = """
action sRShortVec_%s() {
	idx = sfMeta.hashVal;
	sfShortVector.w%s = rShortVec_%s[idx];
}
	"""%(i, i, i)
		print svRW
		print svR

def genLongVecsInline(lvCount):
	print ("// longvec inline")
	for i in range(lvCount):
		svInline = """

/*----------  longVec[%s]  ----------*/
table tiRWLongVec_%s {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_%s; aiRWLongVec_%s;}
}
action aiRWLongVec_%s() {
    sRWLongVec_%s();
}
action aiRLongVec_%s() {
    sRLongVec_%s();
}

register rLongVec_%s {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}
"""%(i, i, i, i, i, i, i, i, i)
		print svInline
	print ("// end longvec inline")

def genLongVecs(lvCount):
	for i in range(lvCount):
		svRW = """
action sRWLongVec_%s() {
	idx = sfMeta.widePtr;
	sfLongVector.w%s = rLongVec_%s[idx];
	rLongVec_%s[idx] = currentPfVec.w0;
}
	"""%(i, i, i, i)
		svR = """
action sRLongVec_%s() {
	idx = sfMeta.widePtr;
	sfLongVector.w%s = rLongVec_%s[idx];
}
	"""%(i, i, i)
		print svRW
		print svR



if __name__ == '__main__':
	main()