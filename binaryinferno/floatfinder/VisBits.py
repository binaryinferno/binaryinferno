


# This file is part of BinaryInferno, a tool for binary protocol reverse engineering.
# Copyright (C) 2023 Jared Chandler (jared.chandler@tufts.edu)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>
#
# QC v.0.1 4/30/2023
#
# =======================================================================================
# __________.__                            .___        _____                           
# \______   \__| ____ _____ _______ ___.__.|   | _____/ ____\___________  ____   ____  
#  |    |  _/  |/    \\__  \\_  __ <   |  ||   |/    \   __\/ __ \_  __ \/    \ /  _ \ 
#  |    |   \  |   |  \/ __ \|  | \/\___  ||   |   |  \  | \  ___/|  | \/   |  (  <_> )
#  |______  /__|___|  (____  /__|   / ____||___|___|  /__|  \___  >__|  |___|  /\____/ 
#         \/        \/     \/       \/              \/          \/           \/        
# ---------------------------------------------------------------------------------------

# FLoat features

import math
from collections import Counter,defaultdict
import statistics
import struct

from sklearn.metrics.cluster import entropy

def H(xs_):
    xs = [str(x) for x in xs_]
    from collections import Counter
    import math
    qty = Counter(xs)
    n = len(xs)*1.0
    tot = 0.0
    for pv in qty:
        v = qty[pv]*1.0
        p =(v/n)
        assert(p<=1)
        #if p == 1.0:
        #    return 0
        if p>=0:
            tot += (p * math.log(p,2))
    return abs(-tot)


# I expect a float
# I Give back a BE bytestring
def floats2byte(x):
	return struct.pack("<f",x)

def bytes2bits(x_,w):
	x = int.from_bytes(x_,'little')
	return [int(((x>>i)&1)!=0) for i in range(w)][::-1]

def int2bits(x,w):
	
	return [int(((x>>i)&1)!=0) for i in range(w)][::-1]


def float_sign(x_):
	x = int.from_bytes(x_,'little')
	return x>>31

def float_exp(x_):
	x = int.from_bytes(x_,'little')
	return (x>>23) & 0xFF

def float_mant(x_):
	x = int.from_bytes(x_,'little')
	return x & 0x7FFFFF

def float_mant(x_):
	x = int.from_bytes(x_,'little')
	return x & 0x7FFFFF

def float_mask(f,m):
	x =int.from_bytes(struct.pack("<f",f),'little')
	return x & m 

get_sign = lambda f: float_mask(f,0x80000000)
get_exp  = lambda f: float_mask(f,0x7F800000)
get_mant      = lambda f: float_mask(f,0x007FFFFF)
get_mant_hi = lambda f: float_mask(f,0x007F0000)
get_mant_mid  = lambda f: float_mask(f,0x0000FF00)
get_mant_lo   = lambda f: float_mask(f,0x000000FF)

def LShape(xs):


	def int2bits(x,w):
		
		return [int(((x>>i)&1)!=0) for i in range(w)][::-1]


	qty = Counter()
	tot_bits = 0
	for x in xs:
		x_f = int.from_bytes(struct.pack("<f",x),'little')
		bits = int2bits(x_f,32)
		for i in range(len(bits)):
			if bits[i]==1:
				qty[i]+=1
				tot_bits+=1

	if tot_bits ==0:
		return 100
	mv = qty.most_common(1)[0][1]*1.0

	max_exp = max([qty[i] for i in range(1,9)])/mv
	avg_mant = sum([qty[i]/mv for i in range(9,32)])/(23.0)
	#if max_exp != 0:
	#	print("Prop E2M",max_mant/max_exp)
	if max_exp != 0:
		return avg_mant/(1.0*max_exp)
	else:
		return 100

def AltLShape(xs):



	def int2bits(x,w):
		
		return [int(((x>>i)&1)!=0) for i in range(w)][::-1]


	qty = Counter()
	tot_bits = 0
	for x in xs:
		x_f = int.from_bytes(struct.pack("<f",x),'little')
		bits = int2bits(x_f,32)
		for i in range(len(bits)):
			if bits[i]==1:
				qty[i]+=1
				tot_bits +=1
	if tot_bits ==0:
		return 100
	mv = qty.most_common(1)[0][1]*1.0
	minv = qty.most_common()[-1][1]*1.0




	max_exp = max([qty[i] for i in range(1,9)])/(1.0*mv)
	max_mant = sum([qty[i]/(1.0*mv) for i in range(9,32)])/23.0
	# if max_exp != 0:
	# 	print("Prop E2M",max_mant/max_exp)
	if max_exp != 0 :
		return max_mant/(1.0*max_exp)
	else:
		return -1

def MantBitVar(xs):


	qty = Counter()
	tot_bits = 0
	for x in xs:
		x_f = int.from_bytes(struct.pack("<f",x),'little')
		bits = int2bits(x_f,32)
		for i in range(len(bits)):
			if bits[i]==1:
				qty[i]+=1
				tot_bits +=1
	if tot_bits ==0:
		return 100
	mv = qty.most_common(1)[0][1]*1.0
	mv = len(xs)
	minv = qty.most_common()[-1][1]*1.0




	#max_exp = max([qty[i] for i in range(1,9)])/(1.0*mv)
	max_mant = statistics.variance([qty[i]/(1.0*mv) for i in range(9,32)])

	return max_mant


def visBits(xs):


	exps = [float_exp(struct.pack("<f",x)) for x in xs]
	mants = [float_mant(struct.pack("<f",x)) for x in xs]
	print("Qty",len(xs))
	print("PercNan",len([x for x in xs if math.isnan(x)])/(1.0*len(xs)))
	print("Var",statistics.variance(xs))
	print("VarInt",statistics.variance([int(x) for x in xs if not math.isnan(x)]))
	print("VarExp",statistics.variance(exps))
	print("VarMant",statistics.variance(mants))
	try:
		print("VarExp/Var",statistics.variance(exps)/statistics.variance(xs))
	except:
		print("VarExp/Var","errr")
	try:
		print("Var/VarExp",statistics.variance(xs)/statistics.variance(exps))
	except:
		print("Var/VarExp","errr")
	print("Min",min(xs))
	print("Max",max(xs))
	if min(xs) >= -1.0 and max(xs) <= 1.0:
		print("Type","Subnormal")
	else:
		print("Type","Normal")

	print("H_exp",H(exps))
	print("H_mant",H(mants))
	print("H_mant_hi",H([get_mant_hi(f) for f in xs]))
	print("H_mant_md",H([get_mant_mid(f) for f in xs]))
	print("H_mant_lo",H([get_mant_lo(f) for f in xs]))

	qty = Counter()

	for x in xs:
		x_f = int.from_bytes(struct.pack("<f",x),'little')
		bits = int2bits(x_f,32)
		for i in range(len(bits)):
			if bits[i]==1:
				qty[i]+=1

	mv = qty.most_common(1)[0][1]*1.0
	minv = qty.most_common()[-1][1]*1.0


	from scipy import stats
	x = [(qty[i]-minv)/(mv-minv) for i in range(9,32)]
	y = [i for i in range(len(x))]

	slope, intercept, r_value, p_value, std_err = stats.linregress(x,y)
	print("R",r_value**2)

	max_exp = max([qty[i] for i in range(1,9)])/mv
	max_mant = sum([qty[i]/mv for i in range(9,32)])/23
	if max_exp != 0:
		print("Prop E2M",max_mant/max_exp)
	head = sum([qty[9],qty[10],qty[11]])
	tail = sum([qty[29],qty[30],qty[31]])
	print("head",head)
	print("tail",tail)
	if tail > 0:
		print("ht_ratio", head/tail*1.0)

	lbl = "S"+"E"*8 + "M"*23
	for i in range(32):
		v = int((qty[i]/mv*1.0)*30)
		pad = 30-v
		v2 = int((qty[i]/(len(xs)*1.0))*30)
		pad2 = 30-v2

		#print(f"{i}\t{lbl[i]}\t{v*'*'}{pad*' '}\t{v2*'*'}{pad2*' '}\t{(qty[i]/mv*1.0)}\t{(qty[i]/len(xs)*1.0)}\t\t{xs[i]}")
		print("vis went here")
		if i == 8:
			print("")

# x = floats2byte(85.125)
# y = floats2byte(-85.125)
# print(x.hex())
# print(y.hex())
# print(bytes2bits(x,32))
# print(int2bits(float_sign(x),1),int2bits(float_exp(x),8),int2bits(float_mant(x),23))
# #,bytes2bits(float_exp(x),32),bytes2bits(float_mant(x),32))
# print(bytes2bits(y,32))

if __name__ == "__main__":

	import random
	import struct

	visBits([random.random() for i in range(1000)])
	# visBits([struct.unpack("<f",struct.pack(">I",random.randrange(0,2**32)))[0]  for i in range(200000)])

	# visBits([random.random()+random.random()  for i in range(200000)])

	# visBits([random.random()  for i in range(200000)])
	# visBits([random.gauss(200,20)  for i in range(200000)])
	# visBits([random.random()*random.randrange(-10,10)  for i in range(200000)])
