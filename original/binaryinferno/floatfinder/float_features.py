
# Extracts features from a possible float.



import struct


# f = 85.125

# # le_xs = struct.pack("<f",f)
# # print(le_xs)
# # print(le_xs.hex())
# # ler_xs = le_xs[::-1]
# # print(ler_xs)
# # print(ler_xs.hex())


# # be_xs = struct.pack(">f",f)
# # print(be_xs)
# # print(be_xs.hex())


def le2be(xs):
	return xs[::-1]


def bei2parts(xs):
	#  unpack gives us (thefloat,)
	f = struct.unpack(">f",xs)[0]

	be_i = int.from_bytes(xs,'big')

	# To determine the sign of the float & to get the high bit
	be_i_sign = int( ( be_i & 0x80000000 ) != 0 )

	# And in the mask and shift over
	be_i_exp = ((be_i & 0x7F800000) >> 23)

	be_i_mant = (be_i & 0x007FFFFF)
	be_i_exp_byte = ((be_i & 0x7F800000) >> 23) & 7
	be_i_mant_byte = ((be_i & 0x007FFFFF) >> 20)
	be_i_mant_cor = (be_i_mant | 0x00800000)
	return {"sign":be_i_sign,"exp":be_i_exp,"exp_byte":be_i_exp_byte,"mant":be_i_mant,"mant_byte":be_i_mant_byte,"mant_cor":be_i_mant_cor,"f":f,"b0":xs[0],"b1":xs[1],"b2":xs[2],"b3":xs[3]}


def prophecyBEF(xs):
	return bei2parts(xs)

def prophecyLEF(xs):
	return prophecyBEF(le2be(xs))

# if the byte order is BIGENDIAN then we don't need to reinterpret the bytes
# be_xs = struct.pack("<f",f)
# #be_xs = le2be(be_xs)
# be_i = int.from_bytes(be_xs,'big')



#print(bei2parts(be_xs))


# print(0xEF800000 & 0x7FFFFF )

# print(0xEF & 0x70)

