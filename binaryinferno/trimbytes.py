#!/usr/local/bin/python3

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

# Utility to trim bytes from segmented ASCII HEX representations

import sys
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL) 


# Drop q hex bytes from the line
def drop(q,line):
    q2 = q *2 # Since we are using hexbytes, double q
    n = 0

    while n < q2:

        x,*line = line
        if x != " ":
            n+=1

    # line is a list of chars
    # So we join and if we happened to break on a space, trim it
    return "".join(line).strip()

assert (drop(3,"XX XXXX YYYY") == "YYYY")
assert (drop(0,"XX XXXX YYYY") == "XX XXXX YYYY")

# Take q hex bytes from the line
def take(q,line):
    q2 = q *2 # Since we are using hexbytes, double q
    n = 0
    res = ""
    while n < q2:
        
        x,*line = line
        if x != " ":
            n+=1
        res+=x

    return res.strip()
    
assert (take(3,"XX XXXX YYYY") == "XX XXXX")
assert (take(0,"XX XXXX YYYY") == "")



left = sys.argv[1]
if len(sys.argv) >= 3:
    right = sys.argv[2]
    right = int(right)
else:
    right = None

left = int(left)






import sys, errno
try:
    with sys.stdin as f1:
        for line in f1:
            # Clean anything at the end
            line = line.strip()

            #line = line.replace(" ","")

            # If the line is not a comment
            if len(line)>0 and line[0] != "#":

                # If we have an lower and upper bound
                if right != None:
                    v1 = drop(left,line)
                    v = take(right-left,v1)
                    sys.stdout.write(v+"\n")
                # Else we only have a lower bound
                else:
                    v = drop(left,line)
                    sys.stdout.write(v+"\n")
                assert (v != "")
            else:
                sys.stdout.write(line)
except IOError as e:
    if e.errno == errno.EPIPE:
        # Handle error
        pass


# data =  sys.stdin.read().strip().split("\n")
# res = []
# for line in data:
#   if len(line)>0 and line[0] != "#":
#       if right != None:
#           res.append(line[left*2:right*2])
#       else:
#           res.append(line[left*2:])
#   else:
#       res.append(line)


# res = "\n".join(res)
# sys.stdout.write(res)
# sys.stdout.flush()
