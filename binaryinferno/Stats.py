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
from collections import Counter,defaultdict

def branch():
	index = sys.argv[1]
	xs = index.strip().split(":")
	xs = [x for x in xs]
	if len(xs) == 1:
		i = int(xs[0])
		j = i+1
	if len(xs) == 2:
		i = int(xs[0])
		j = int(xs[1])

	if len(xs) > 2:
		print("index too big")
		quit()

	def gettag(line):
		ys = [y for y in bytes.fromhex(line)]
		return bytes(ys[i:j]).hex()

	data = sys.stdin.read()
	lines = data.strip().split("\n")
	branches = defaultdict(lambda:[])

	if len(sys.argv) > 2:
		show_tag = sys.argv[2].strip()
	else:
		show_tag = None

	for line in lines:
		tag = gettag(line)

		# if show_tag == None:
		# 	print(tag,line)
		branches[tag].append(line)
	if show_tag == None:
		#print("")
		
		for key_s in sorted(branches):
			key = bytes.fromhex(key_s)
			#print(key,type(key))
			diflens = len(set([len(m) for m in branches[key_s]]))
			varlen =not diflens==1
			key_int = [0]*(4-len(key)) + [b for b in key]
			ki= int.from_bytes(key_int,'big')
			if varlen:
				vls = "Variable"
			else:
				vls = "Fixed"
			print(key_s,ki,len(branches[key_s]),vls,diflens) 
	else:
		for line in branches[show_tag]:
			print(line)


	



# def main():
# 	import sys
# 	from collections import Counter
# 	data = sys.stdin.read()
# 	lines = data.strip().split("\n")
# 	q = Counter()
# 	lens = [len(l) for l in lines]
# 	uniq = len(set(lines))
# 	for l in lines:
# 		q[len(l)]+=1

# 	for k,v in q.most_common():
# 		print(k,v)
# 	print("Qty Distict",uniq)
# 	print(min(lens)+1)


def filterlen():
	k = int(sys.argv[1])
	data = sys.stdin.read()
	lines = data.strip().split("\n")
	for l in lines:
		if len(l) == k*2:
			print(l)
	
def main():

	data = sys.stdin.read()
	lines = data.strip().split("\n")
	q = Counter()
	lens = [int(len(l.strip())/2.0) for l in lines]
	#print(lens)
	uniq = len(set(lines))
	for l in lines:
		q[int(len(l)/2.0)]+=1

	for k,v in q.most_common():
		print(k,v)
	print("Qty Distict",uniq)
	print(int((min(lens)+1)))


if __name__ == '__main__':

	if len(sys.argv) > 1:
		
		if ":" in sys.argv[1]:
			branch()
		else:
			filterlen()
		#print("index",index)
	else:
		main()
