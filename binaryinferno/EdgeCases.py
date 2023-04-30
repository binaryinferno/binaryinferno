

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


from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from deconflict import deconflict

import struct
import statistics






def bytes2int(xs):
    pad= 4-len(xs)
    return struct.unpack(">I",bytes([0]*pad + xs))[0]


def sequenceHeur(xs):
    n = 0
    gt = 0

    for i in range(len(xs)-1):
        n+=1
        if xs[i]<xs[i+1]:
            gt+=1
    return gt/(1.0*n)

def inferconst(txt,valuescale,LE=True,width=4):
    if LE:
        endian = "LE"
    else:
        endian = "BE"
    xs = hexmsgs(txt)
    n = len(xs)
    #print(xs)

    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-(width-1)

    sigmas = []
    for i in range(max_k):
        
        ys = [x[i:i+width] for x in xs]

        if len(set(ys)) ==1:
            
            intervals = [INTERVAL("C",i,i+width) for x in xs]
            s = SIGMA([FIELD(intervals,annotation= endian + " Constant" +str(width*8) + "(" +str(ys[0].hex())+")",valuescale=valuescale)])
            sigmas.append(s)
    #print("Floatfinder found",sigmas)
    if len(sigmas)>=1:
        return sigmas
    else:
        return []



# def inferseqLE(txt,valuescale=.1,width=4):
#     return inferseq(txt,valuescale,True,width)

# def inferseqBE(txt,valuescale=.1,width=2):
#     return inferseq(txt,valuescale,False,width)


# inferseq8BE = lambda txt,valuescale=.1: inferseqBE(txt,valuescale,1)
# inferseq16BE = lambda txt,valuescale=.1: inferseqBE(txt,valuescale,2)
# inferseq24BE = lambda txt,valuescale=.1: inferseqBE(txt,valuescale,3)
# inferseq32BE = lambda txt,valuescale=.1: inferseqBE(txt,valuescale,4)


# inferseq8LE = lambda txt,valuescale=.1: inferseqLE(txt,valuescale,1)
# inferseq16LE = lambda txt,valuescale=.1: inferseqLE(txt,valuescale,2)
# inferseq24LE = lambda txt,valuescale=.1: inferseqLE(txt,valuescale,3)
# inferseq32LE = lambda txt,valuescale=.1: inferseqLE(txt,valuescale,4)


def inferconst32(txt,valuescale=.1,width=4):
    return inferconst(txt,valuescale,True,width)

if __name__ == "__main__":



    txt = """?
    --
    000000001101
    110000001102
    4a0000001103
    ac0000001104
    b20000001105
    c20000001106
    --
    """

    txt2 = """?
    --
    000003bf0008fc38422651c5c2ebc4e6
000003c00008fc3742261326c2edb302
000003c30008fc34422496ffc2ebe1ed
000003c60008fc3142239845c2ed653d
000003c70008fc3042223086c2edc73e
000003c90008fc2e4221f696c2eefc0c
000003cd0008fc2a422392fac2efd493
000003ce0008fc2942232e03c2f01e09
000003d00008fc274221f020c2f1cb8d
000003d20008fc254221df5ec2f2d79e
000003d70008fc2042229428c2f39280
000003de0008fc1942231a4bc2f39609
000003e00008fc174224309ec2f26080
000003e10008fc16422501edc2f0dbda
000003e20008fc15422399cac2ef6fe4
000003e50008fc12422238c7c2efae23
000003e60008fc114220a0b7c2f0fbba
--"""
    res = inferconst32(txt)
    print(res)

    x= res[0].apply(txt)
    print(x)

    # print("")