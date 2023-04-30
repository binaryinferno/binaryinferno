

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

# Are the IPs?

from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from deconflict import deconflict

d1 = """
?
--
00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
--"""

foo = """
Motivation:

An IP address should never start with 0
An IP Address should never end with 0
First Octet should be below 240"""


def isip(xs):

    return xs[0] > 0 and xs[0] <240 and xs[3] > 0 






def inferip(txt):
    xs = intmsgs(txt)
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-3

    sigmas = []
    for i in range(max_k):
        ys = [x[i:i+4] for x in xs]
        are_ips = [isip(y) for y in ys]
        #print(i,all(are_ips),ys)
        if all(are_ips):
            intervals = [INTERVAL("C",i,i+4) for x in xs]
            s = SIGMA([FIELD(intervals,annotation="IP Address",valuescale=.1)])
            sigmas.append(s)
    print("IPfinder found",sigmas)
    print(len(sigmas))
    if len(sigmas)>1:
        return sigmas
    elif len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas
if __name__ == "__main__":

    for s in inferip(d1):
        print(s)

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")