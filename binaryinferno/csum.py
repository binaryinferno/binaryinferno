

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


# Related work inferring checksums



from sumeng_module_beta import sumeng
from Sigma import ascii2sigma,hexmsgs,msgs,SIGMA,FIELD,INTERVAL

d1 = """
?
--
00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
--"""


#depending on width, figure out what the real number should be
def translateindexs(i,w):
	if w == 8:
		return i
	else:
		j = i*2
		return j
		# 0 = 0
		# 1 = 2
		# 2 = 4
		# 3 = 6


def inferchecksum(txt):
	raw_msgs = msgs(txt)
	hex_msgs = hexmsgs(txt)
	n_lines = len(raw_msgs)
	lines = "\n".join(raw_msgs)
	sigmas = []
	#print(lines)
	for w in [16,8]:
		if w == 16:
			s = 2
		else:
			s = 1
		res = sumeng(msgs=lines,width=w)


		# print("*"*80)
		# for r in res:
		#     print(r)

		if len(res) > 0:
			#print(w,res)
			for r in res:
				result = r[1]

				entropy,start,stop,index,op,finop,magic,coverage = result

				#How well does the checksum uniquely describe the messages

				usefulness = (2**entropy)/len(raw_msgs)

				if usefulness > .5 and coverage >= .5:
					if stop == 0:
						stop = "END"
					annotation = "Checksum Algorithm ( width="+str(w)+" index="+str(index)+" "+str(round(entropy,2))+":"+str(round(usefulness,2))+")= Op:" + str(op) + " FinOp:" + str(finop) + " Magic:" + str(magic) + " Payload:" +str(start) + " to " + str(stop)
					if index < 0:
						#s1 = SIGMA([FIELD([INTERVAL("X",index,index+1) for i in range(n_lines)])])
						intervals = [INTERVAL("X",(s*len(hm))+(s*index),(s*len(hm))+(s*index)+(s*1)) for hm in hex_msgs]
						s1 = SIGMA([FIELD(intervals,annotation=annotation)])
					else:
						s1 = SIGMA([FIELD([INTERVAL("X",(s*index),(s*index)+(s*1)) for i in range(n_lines)],annotation=annotation)])
					sigmas.append(s1)
	if sigmas != []:
		return sigmas

	return SIGMA([])

if __name__ == "__main__":

	s1 = inferchecksum(d1)
	print(s1)
	print(s1.apply(d1))
	s0 = SIGMA([])
	print(s0.apply(d1))