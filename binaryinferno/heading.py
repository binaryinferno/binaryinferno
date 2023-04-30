

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

# Deprecated attempt at determining field is compass headings

from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from deconflict import deconflict

d1 = """
?
--
fe14ef01014a0000000080249f40850148425b9606bac3ff31001363
fe14ef01014a0000000091dd9f40de014842d0a000baae0030008e60
fe14ef01014a00000000edc9963c01cae341c496cebbfdff0000c206
fe14f201014a0000000084709f4086017042774b01bb9aff31003f73
fe14f301014a00000000482aa040f90848424c1bd1bb420030008fa6
fe14f501014a00000000336ca0404b034842778281bb7d003100473b
fe14f501014a000000003af4ec3db0044842721ad7bbc1ff3100f92c
fe14f501014a0000000075a29f40aaff4742b7b5bab97d003100a5d2
fe14f501014a000000009a65a14006126a429611fcbc3d003100cb8f
fe14f501014a00000000c4d2a0402b0648428a63dbbb7d00310013e7
fe14f601014a000000003a6a933cced9e34128a67dbb11000000cef4
fe14f601014a00000000ee559e4030f369421af3a63a3d0031000017
fe14f701014a000000005690a04036fc4742c5e9b33bfcff3000fd49
fe14f801014a000000007bfae83eb7a92d429bcf7fbf0d003000bdd0
fe14f801014a000000008c83a63c4ceee241a498b13d0e000c004bb3
fe14fd01014a000000009931a240ee11484271fd7dbc7d0030003135
fe14fd01014a00000000aac79e409d04484291be9cbbc3ff310017c2
fe14fd01014a00000000df64ab3eac1e484277f4dbbcc1ff3100b4cc
fe14ff01014a000000005de85d3bf10ae441425c1ebb000000001bae
--"""

foo = """
Motivation:

An IP address should never start with 0
An IP Address should never end with 0
First Octet should be below 240"""


def areheadings(xs,order):
    #int.from_bytes( bytes, byteorder, *, signed=False )
    hs = [int.from_bytes(x,order) for x in xs]
    #print(min(hs)>=0 and max(hs)<= 360 and len(set(hs))>1,"headings",hs)
    return min(hs)>=0 and max(hs)<=360 and len(set(hs)) >1


def inferheading(txt):
    xs = intmsgs(txt)
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-1

    sigmas = []
    for i in range(max_k):
        ys = [x[i:i+2] for x in xs]
        #are_ips = [isip(y) for y in ys]
        #print(i,all(are_ips),ys)

        if areheadings(ys,'little'):
            intervals = [INTERVAL("H",i,i+2) for x in xs]
            s = SIGMA([FIELD(intervals,annotation="LE Heading 0-360",valuescale=.2)])
            sigmas.append(s)
        # if areheadings(ys,'big'):
        #     intervals = [INTERVAL("H",i,i+2) for x in xs]
        #     s = SIGMA([FIELD(intervals,annotation="BE Heading 0-360",valuescale=.1)])
        #     sigmas.append(s)

    # print("IPfinder found",sigmas)
    # print(len(sigmas))
    if len(sigmas)>1:
        return deconflict(sigmas)
    elif len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas[0]
if __name__ == "__main__":

    for s in inferheading(d1):
        print(s)

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")