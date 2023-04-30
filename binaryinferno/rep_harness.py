

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


# Serialization Pattern Search

import sys
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL

sys.path.append('./rep_finding')

from rep_infer import infer_reps


#s = SIGMA([FIELD(intervals,annotation= endian + " Float " + "min("+str(min(fs))+") max(" +str(max(fs))+") mean(" +str(statistics.mean(fs))+") stdev(" +str(statistics.stdev(fs))+")",valuescale=valuescale)])


def text2repsigmas(rawmsgs):
	rawmsgs = rawmsgs.strip()
	print("msgs",rawmsgs)
	try:

		model_txt = "\n".join(msgs(rawmsgs))
		print("model_txt",model_txt)
	except:
		model_txt= rawmsgs


	# Try to get 3 inferred solutions for the input	
	res = infer_reps(model_txt,qtysols=3)

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
			raw_fields.append([])
			for row in r:
				#print(field_index,"\t\t",row[field_index])
				raw_fields[-1].append(row[field_index])

		#intervals = [INTERVAL("F",i,i+4) for x in xs]
		fields = []
		for raw_field in raw_fields:
			intervals = []
			for interval in raw_field:
				intervals.append(INTERVAL("R",interval[1],interval[2]))
			annotation = raw_field[0][0]
			field = FIELD(intervals,annotation=annotation,valuescale=.9)
			fields.append(field)
		s = SIGMA(fields)
		sigmas.append(s)
	return sigmas


if __name__ == '__main__':
	model_txt =  sys.stdin.read()
	sigmas = text2repsigmas(model_txt)
	for s in sigmas:
		print(s,[f.annotation for f in s.fields])
		#print(s)
		pass
