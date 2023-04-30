

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




# Should't see vertical slices of bytes with different entropy such as constant values or zeros in the interior
def hasstripes(xs,endian):
    import re
    if endian == "BE":
    	endflag = -1
    else:
    	endflag = 1
    slices = [ [y[::endflag][i]for y in xs] for i in range(len(xs[0]))]
    def isconst(xs):
        if len(set(xs))==1:
            return 'c'
        else:
            return 'n'

    s = "".join([isconst(x) for x in slices])
    s = re.sub('c+','c',s)
    s = re.sub('n+','n',s)
    
    #print("stripes",endian,s)
    return "ncn" in s or "cn" in s or "cnc" in s



def main():
	import sys
	data = sys.stdin.read().strip()
	lines = [d.strip() for d in data.split("\n")]
	for l in lines[:10]:
		print(l)
	print("Has Stripes BE?",hasstripes(lines,"BE"))

	print("Has Stripes LE?",hasstripes(lines,"LE"))
if __name__ == '__main__':
	main()