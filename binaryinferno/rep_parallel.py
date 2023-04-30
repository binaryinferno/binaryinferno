

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


import sys
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
import argparse
import pickle


sys.path.append('./rep_finding')

from rep_infer_push import infer_reps



# Example Invocation
# cat safedocs_deliverables/rep_finding/nums.txt | parallel --halt now,success=1 "python3 rep_parallel.py --offset {} --txtfile safedocs_deliverables/rep_finding/dhcp.txt"
# cat safedocs_deliverables/rep_finding/nums.txt | parallel --halt now,success=1 "python3 rep_parallel.py --offset {} --txtfile safedocs_deliverables/rep_finding/dhcp_big.txt"
# cat safedocs_deliverables/rep_finding/nums.txt | parallel --halt now,success=1 "timeout 60s cat safedocs_deliverables/rep_finding/dhcp_big.txt | python3 rep_parallel.py --offset {}"
# s = SIGMA([FIELD(intervals,annotation= endian + " Float " + "min("+str(min(fs))+") max(" +str(max(fs))+") mean(" +str(statistics.mean(fs))+") stdev(" +str(statistics.stdev(fs))+")",valuescale=valuescale)])




def text2repsigmas(rawmsgs,offset,fname,shortcircuit,filterrules,push):
	print("text2repsigs",push)
	rawmsgs = rawmsgs.strip()
	print("msgs",rawmsgs)
	try:

		model_txt = "\n".join(msgs(rawmsgs))
		print("model_txt",model_txt)
	except:
		model_txt= rawmsgs
	#txtmsgs,offset=0,txtfile=None,qtysols=1,mhl=300,answerfmt=False
	res = infer_reps(model_txt,offset=offset,txtfile=fname,qtysols=20,shortcircuit=shortcircuit,filterrules=filterrules,push=push)
	#def infer_reps(txtmsgs,offset=0,txtfile=None,qtysols=1,mhl=300,answerfmt=False):

	sigmas = []
	# For each inferred description
	for r in res:
		#print(r)

		raw_fields = []
		# How many fields are there in here? 
		# Each row of data should have 
		qty_fields = len(r[0])
		#print(qty_fields)
		for field_index in range(qty_fields):

			# Create a field
			raw_fields.append([])
			for row in r:
				#print(field_index,"\t\t",row[field_index])

				# For the field we just created, add in the interval data (name, start, stop)
				raw_fields[-1].append(row[field_index])

		#intervals = [INTERVAL("F",i,i+4) for x in xs]
		fields = []
		for raw_field in raw_fields:
			intervals = []
			for interval in raw_field:
				intervals.append(INTERVAL("R",interval[1],interval[2]))
			annotation = raw_field[0][0]
			field = FIELD(intervals,annotation=annotation,valuescale=1.0)
			fields.append(field)
		s = SIGMA(fields)
		sigmas.append(s)
	return sigmas




if __name__ == '__main__':

	xparser = argparse.ArgumentParser()

	xparser.add_argument("-q",   "--txtfile", default=None,                 help="file")
	xparser.add_argument("-y",   "--offset", type=int,                 help="byteoffset",default = 0)
	xparser.add_argument("-p",   "--push", type=int,                 help="pushoffset",default = 0)
	xparser.add_argument("-c",   "--shortcircuit", type=int,                 help="shortcircuit",default = None)
	xparser.add_argument("-e",   "--filterrules", type=str   ,help="filterrules", default = None)

	xargs = xparser.parse_args()

	print("all rep_parallel.py args parsing done")
	print("### rep_parallel.py called with",xargs,"###")

	if xargs.txtfile == None:
		rawmsgs = sys.stdin.read()

		sigmas = text2repsigmas(rawmsgs,xargs.offset,xargs.txtfile,xargs.shortcircuit,xargs.filterrules,xargs.push)
	else:
		sigmas = text2repsigmas("",xargs.offset,xargs.txtfile,xargs.shortcircuit,xargs.filterrules,xargs.push)
	if sigmas == []:
		print([SIGMA([])])
		#print("<<<"+pickle.dumps([SIGMA([])]).hex()+">>>")
		#print(xargs.offset,"finished clean")
		sys.exit(1)

	else:
		for s in sigmas:
			print("@@@",xargs.offset,xargs.shortcircuit,s,[f.annotation for f in s.fields],"@@@")
		#print(xargs.offset,"finished clean")
		#print("<<<"+pickle.dumps(sigmas).hex()+">>>")
		sys.exit(0)


