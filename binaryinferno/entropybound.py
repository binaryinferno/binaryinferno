

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

# Entropy Boundary Detectors





from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL,apply
from deconflict import deconflict
from Weights import WCAT1,WCAT2,WCAT3

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



def H(xs_):

    from collections import Counter
    import math

    # Convert our input list to strings. This lets the counter handle weird data types like lists or bytes
    xs = [str(x) for x in xs_] 

    # Count things up
    qty = Counter(xs)

    # How many things do we have?
    n = len(xs)*1.0

    # This is what we will add the summation to
    tot = 0.0

    # For item in the counter
    for item in qty:
        # Get our quantity
        v = qty[item]*1.0

        # Convert that to a probability
        p =(v/n)

        assert(p<=1) #Can't have probability greater than 1 

        # If our probability is greater than zero:
        if p>=0:
            # Add to the total 
            tot += (p * math.log(p,2))
    return abs(-tot)








def inferentropybound(txt,LE=True):
    xs = intmsgs(txt)
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-1

    sigmas = []
    for i in range(max_k):
        ys = [x[i] for x in xs]
        zs = [x[i+1] for x in xs]

        if LE == True:
            H_ys = H(ys)
            H_zs = H(zs)
        else:

            # BigEndian
            # Reverse the order
            H_ys = H(zs)
            H_zs = H(ys)

        # Is there more than 1 bit of difference between the two sides? 
        # WHich means double the amount information on one side vs the other
        if (H_zs - H_ys) >= 1:
            intervals = [INTERVAL("|",i+1,i+1) for x in xs]
            f = FIELD(intervals,valuescale=WCAT3)
            f.annotation = str(H_zs) + " - " + str(H_ys) + " = " +  str(H_zs - H_ys)
            print(f,f.annotation)
            s = SIGMA([f])
            sigmas.append(s)


    if len(sigmas)==1:
        return sigmas[0]
    elif len(sigmas) == 0:
        return SIGMA([])
    else:
        return deconflict(sigmas)

def inferentropyboundLE(txt):
    return inferentropybound(txt,True)

def inferentropyboundBE(txt):
    return inferentropybound(txt,False)
if __name__ == "__main__":

    res = inferentropybound(d1)
    print(res)
    print(res.apply(d1))

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")