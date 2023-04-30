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

import pickle
import sys
import os

if len(sys.argv) <=1:
    print("usage: python3 dumper.py filetodump")
    quit()

def file2model(fname):
    f = open(fname,'rb')
    data = pickle.load(f)
    gt = data["gt"]
    model = data["model"]
    f.close()
    return gt,model

gt,msgs = file2model(sys.argv[1])
for m in msgs:
	print(bytes(m).hex())

# files = os.listdir(sys.argv[1])

# for f in files:
# 	fname = sys.argv[1]+"/"+f
# 	gt,msgs = file2model(fname)

# 	fh = open("example_data_text/"+f,"w")
# 	fh.write(str(msgs))
# 	fh.close()