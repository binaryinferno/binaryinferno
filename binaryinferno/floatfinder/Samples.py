

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



from VisBits import LShape,AltLShape,MantBitVar
from collections import defaultdict,Counter
from float_features import prophecyBEF,prophecyLEF

import struct
import statistics
import math
import sys
import numpy as np
np.seterr(all='ignore')


badvar = 0



from collections import Counter,defaultdict

# ---------------------------
# Enropy calculation function
#
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




# Given a set of values interpret as BE and get some data
def calcBEMeasuresOfSlice(WINDOW,xs):
	cols = defaultdict(lambda:[])
	for x in xs:
		assert(len(x)==WINDOW)
		m = prophecyBEF(x)
		for k in m:
			cols[k].append(m[k])

	return cols

def var(xs,f):
	#v = statistics.variance(xs)
	#
	xs_ = [np.frombuffer(struct.pack("<f",x),dtype=np.float32) for x in xs]
	v = np.var(xs_)
	v = statistics.variance(xs)
	if np.isfinite(v):
		if v > np.iinfo(np.uint32).max:
			return np.iinfo(np.uint32).max
		else:
			if v < np.iinfo(np.uint32).min:
				return np.iinfo(np.uint32).min
			else:
				return v
	else:
		return -1
	return v
	if math.isnan(v) or v == float("inf") or v== float("-inf"):# or v >= 2**64: #v >= sys.float_info.max:
		print("bogus v",f,v,type(v))

		return np.iinfo(np.uint32).max
	else:
		print("not bogus v",f,v)
		return v

# THis mustttt have bugs
def calcDimensions(cols):

	# Constant
	def allsame(xs):
		return len(set(xs))==1


	def allvalue(xs,v):
		if allsame(xs):
			if xs[0] == v:
				return True
			else:
				return False
		else:
			return False
	# These are always zero
	def allzero(xs):
		return allvalue(xs,0)

	# Zero never shows up
	def allnonzero(xs):
		return len(xs) == len([x for x in xs if x != 0])
	dims = {}


	
	dims["f_var"] = var(cols["f"],"f")
	dims["exp_var"] = var(cols["exp"],"exp")
	dims["mant_var"] = var(cols["mant"],"mant")
	dims["mant_byte_var"] = var(cols["mant_byte"],"mant_byte")
	dims["mant_cor_var"] = var(cols["mant_cor"],"mant_cor")
	dims["lshape"] = LShape(cols["f"])
	dims["altlshape"] = AltLShape(cols["f"])
	dims["bitvar"] = MantBitVar(cols["f"])

	xs = cols["f"]

	# dims["exp_mant_byte_H_dff"] = H(cols["exp_byte"]) - H(cols["mant_byte"])

	# num = H(cols["exp_byte"]) 
	# den = H(cols["mant_byte"])*1.0

	# if den == 0:
	# 	if num == 0:
	# 		vv = 0
	# 	else:
	# 		vv = 512/1.0
	# else:
	# 	vv = num/den
		
	# dims["exp_mant_byte_H_div"] = vv

	fields = ["f","exp","mant","mant_cor","b0","b1","b2","b3"]
	for field in fields:

		#dims["h_"+field] = H(cols[field])
		for fname,f in [("allsame",allsame),("allzero",allzero),("allnonzero",allnonzero)]:

			field_fname = field+"_"+fname
			v = int(f(cols[field]))
			dims[field_fname] = v

	return dims





def sliceDataset(WINDOW,xs,gt):
	res = []
	xs_w = len(xs[0])
	#print("xs_w",xs_w)
	#ground_truths = [0]*(xs_w)
	for k in range(xs_w-WINDOW+1):
		vs = [z[k:k+WINDOW] for z in xs] # Slice
		cols = calcBEMeasuresOfSlice(WINDOW,vs)
		dims = calcDimensions(cols)
		res.append({"k":k,"gt":gt[k],"values":vs,"dims":dims})
	return res



def makeSamples(WINDOW,fields):

	bs = [f[0] for f in fields]
	gts = [f[1] for f in fields]

	qty_msgs = len(bs[0])

	msgs = []

	for i in range(qty_msgs):
		msg = b''
		for k in range(len(fields)):
			#print(bs[k][i])
			msg+=bs[k][i]
		msgs.append(msg)

	xs = msgs
	gt = []
	for g in gts:
		gt+=g



	samples = sliceDataset(WINDOW,xs,gt)


	res = []

	# +1 from strart -4 from end
	# 1 1 1 1 2 2 2 2 3 3 3  3
	#.  X X X X 
	# 0 1 2 3 4 5 6 7 8 9 10 11 
	#print("len samples",len(samples))

	# for i in range(1,8):
	for i in range(1,len(samples)-1):
	#for i in range(1,len(samples))
		# s = samples[i]
		# gt = int(s["gt"]=="f1")
		# res.append({"gt":gt,"dims":s["dims"]})

		if True:
			s3 = samples[i-1]
			s4 = samples[i]
			s5 = samples[i+1]

			gt2 = (s3["gt"],s4["gt"],s5["gt"])
			gt = int((s4["gt"] == "f1")) #Is this thing actually an Float
			f_var34 = s3["dims"]["f_var"]-s4["dims"]["f_var"]
			f_var45 = s4["dims"]["f_var"]-s5["dims"]["f_var"]

			new_dims = {"pred_field_f_var34":f_var34,"field_succ_f_var45":f_var45,"pref_f_var":s3["dims"]["f_var"],"field_f_var":s4["dims"]["f_var"],"succ_f_var":s5["dims"]["f_var"]}
			new_dims.update(s4["dims"])
			res.append({"gt":gt,"gt2":gt2,"dims":new_dims})
	return res
