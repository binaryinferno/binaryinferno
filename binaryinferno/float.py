

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

# Harness for the floatfinder down in floatfinder


import sys
sys.path.append('./floatfinder')

from Weights import WCAT3

from FloatFinder import predictfloat


from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from deconflict import deconflict

import struct
import statistics

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



# Squeeze the floats into a smaller space causing exponent overlap



def squeeze(xs,fmt):
    print(type(xs[0]))
    zs = []
    for x in xs:
        #print(x)
        y = struct.unpack(fmt,x)[0]*.00001
        #print(y)
        z = struct.pack(fmt,y)
        zs.append(z)

    #print(type(zs[0]))
    return zs



def inferfloat(txt,valuescale,isLE=True):
    if isLE:
        endian = "LE"
        xs = hexmsgs(txt)
        #xs = squeeze(xs,"<f")
    else:
        endian = "BE"
        xs = hexmsgs(txt)
        #xs = squeeze(xs,">f")
    n = len(xs)
    #print(xs)

    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-3

    sigmas = []
    for i in range(max_k):
        # Flips for little endian data, allowing same code to handle both cases.
        # Only dif between big and little endian floats is byte order so we can use [::-1]
        if isLE:

            ys = [x[i:i+4][::-1] for x in xs]
            #ys = squeeze(ys,">f")
        else:
            ys = [x[i:i+4] for x in xs]
            #ys = squeeze(ys,">f")

            

        if predictfloat(ys,LE=isLE):
            fs = [struct.unpack(">f",y)[0] for y in ys]
            intervals = [INTERVAL("F",i,i+4) for x in xs]
            s = SIGMA([FIELD(intervals,annotation= endian + " Float " + "min("+str(min(fs))+") max(" +str(max(fs))+") mean(" +str(statistics.mean(fs))+") stdev(" +str(statistics.stdev(fs))+")",valuescale=valuescale)])
            sigmas.append(s)
            
    #print("Floatfinder found",sigmas)
    if len(sigmas)>1:
        return deconflict(sigmas)
    elif len(sigmas) == 0:
        return SIGMA([])
    else:
        return sigmas[0]


def inferfloatLE(txt,valuescale=WCAT3):
    return inferfloat(txt,valuescale,True)

def inferfloatBE(txt,valuescale=WCAT3):
    return inferfloat(txt,valuescale,False)

if __name__ == "__main__":

    for s in inferfloatLE(d1):
        print(s)

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")