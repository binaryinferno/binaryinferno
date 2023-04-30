

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

# This file performs a parallel serialization pattern search via the gnu-parallel command in
# rep_parallel.sh

from Sigma import ascii2sigma,bytes2ascii,intmsgs,hexmsgs
from Sigma import msgs as msgsf

def rep_par_BE(msgs,mml=1000):
	return rep_par(msgs,mml=mml,endianess="BE")

def rep_par_LE(msgs,mml=1000):
	return rep_par(msgs,mml=mml,endianess="LE")


def rep_par(msgs,mml=1000,endianess="XE"):
	# mml = min([len(m) for m in msgs])

	# # if type(msgs)==type(bytes()):
	# print(type(msgs),len(msgs))
	# for m in msgs.split("\n"):
	# 	print("\t",m)
	msgs = msgs.replace("\t","")
	msgs = msgs.replace(" ","")
	if "--" in msgs:
		msgs = msgs.split("--")[1]

	import sys
	import re
	import pickle
	#data = sys.stdin.read()
	# print("Data is len",len(data))

	import subprocess
	# Where 1000 is min message length
	cmd = ['./rep_parallel.sh '+str(mml) + " " + endianess] #['awk', 'length($0) > 5']
	in_data = msgs.encode('utf-8')
	result = subprocess.run(cmd, stdout=subprocess.PIPE, input=in_data,shell=True,stderr=subprocess.PIPE )#, input=ip)
	data = result.stdout.decode('utf-8').strip()
	print("data",len(data))
	sigmas = []
	for m in re.findall("<<<([a-z0-9]*?)>>>",data,flags=re.MULTILINE):
		#print("m")
		sigmas+= pickle.loads(bytes.fromhex(m))
		#print("m",sigmas)
	sigmas = sorted(sigmas,key=lambda s:(len(s.fields),-sum([f.value for f in s.fields]) ))[:100]
	#sigmas = sigmas[:1]
	return sigmas

def main():

	import sys

	if len(sys.argv) == 2:
		endianess = sys.argv[1]


	else:
		endianess = "XE"
	data = sys.stdin.read()
	sigmas = rep_par(data,endianess=endianess)
	print("Got ",len(sigmas),"sigmas")
	#sigmas = sorted(sigmas,key=lambda s:len(s.fields))
	for s in sigmas: #sorted(sigmas,key=lambda s:-sum([f.value for f in s.fields])): # s:len(s.fields)):
		print(len(s.fields),sum([f.value for f in s.fields]),[f.annotation for f in s.fields],[f.value for f in s.fields],s)

	# sub = defaultdict(lambda:[])
	# for i in range(len(sigmas)):
	# 	for j in range(i,len(sigmas)):
	# 		if i != j:
	# 			print(i,j,sigmas[i]==sigmas[j])


if __name__ == '__main__':
	main()