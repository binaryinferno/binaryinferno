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

# Some unit testing stuff, but you could just run these on the command line.


import random
import struct

DIR = "unit_tests/"
# LV

def mkvs():
	return random.randrange(0,256)

def write_unit_test(res,fname):
	f = open(DIR+ fname,"w")
	bs = [bytes(r).hex() for r in res]
	f.write("\n".join(bs))
	f.close()


for l_width in range(1,5):

	res = []

	max_l = (2**(8*(l_width-1)))
	max_l = min(max_l,200000)
	#max_l = 5
	#max_l = 255
	for i in [0,1,2,max_l]:

		
		l = i
		v = l*[mkvs()]
		l_bytes = [x for x in struct.pack(">I",i)][-l_width:]
		print(l_width,i,l_bytes)
		msg = l_bytes+v
		res.append(msg)

	fname = "L" * l_width + "V.txt"
	write_unit_test(res,fname)
