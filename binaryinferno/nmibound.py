


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




from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL,apply
from deconflict import deconflict
from sklearn.metrics.cluster import normalized_mutual_info_score

NMI = normalized_mutual_info_score

d1 = """
?
--
00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
--"""

d1 ="""
?
--
    fe3e40010169df32ab000000000074c74c3beff57fbc8b191dc1da160e3cea9798bb324a4cbce21a673f6fdc0e3d0e7de53fc23ac547000000001b14e54100000042ff1beaa0
    fe3e9401016967cb881000000000a1b9a4bde52b46bd9e7d1dc133f272bc5581163ebd03723c3d8f3c3f1806d9bd22deed3f06bbc4470000000019f3474200000042ff1beadc
    fe3e95010169af437c090000000080d344bece0991bc79971cc136ce0d3c9b9f863cd51a9e3b8cd4b1bee0424e3f0f84e63f357fc4470000000021ff6f4200000042ff1b128b
    fe3ee40101696d32680a00000000b5c68abe01e8e6bce78f1bc1d8099f3a9c14e03c8a5933bb62aab7be079b553f376ee43f2f7fc44700000000d601704200000042ff1b7aa9
    fe3e160101694bbe450500000000ec72e0bc6b561a3da97d1cc1e8c99d3b2b1c41bc1314f03b3adf673f6585c03c17cde33f093cc547000000003063e34100000042ff1b25df
    fe3e810101692b3e9f150000000015da63be32f93bbece1a1dc1d779d7bb1de21abc7961d03b369c84be412652bf3fb3e63fa3b9c447000000007fde484200000042ff1bc927
    fe3e7401016906a5c104000000001ba5243dd6ec82bd69a51cc11ba90e3b3726933a4461a73b3801653f54f00f3da42ce53fde3bc547000000004d99e34100000042ff1bedfb
    fe3ef3010169bc97ac21000000008a3ed3be64227bbe91f21cc14b73d5bc6a8c653b24c3c9bc4623763e1058693f1786e13f26bbc4470000000074dd474200000042ff1bc73a
    fe3e92010169ee332c0e00000000d51fc1be4e4151be69e31cc1729e263b1e18a7bb80609ab8779d6c3f4066b03e47d0dd3f62bac44700000000545f484200000042ff1b7166
    fe3e1b0101697adb281d000000003d6d46be2dcc66be08e31cc18be81bbcc27e5abbf108b33b21a545bf5621c93e01b7e73f7cbac44700000000184f484200000042ff1b1d21
    fe3e32010169e9669c12000000001a80a3bef60e53be8b9c1cc19de3a0bcb585edbadc836d3a2d5e1a3fffe62abfae2fe53f22bbc4470000000029e0474200000042ff1b8996
    fe3ee7010169a0a1030e000000008c958cbeb6d9cdbdb8891cc1b6e096baf4c4b5bcf8d643bba713673f3b7f953e06e2e13fbbbac44700000000cd23484200000042ff1be986
    fe3e500101692ac65210000000006431abbdab9e8d3d970f1ec14185fd3deae99a3cad2130bc82cd733fbb10b53e95f2db3facbbc447000000007581474200000042ff1b6d8c
    fe3e79010169f3a1af0400000000140bda3ca0ae163cc0571cc18c71a23b9a54fbbbf00380bc47bc663fa2e7e03c1985e43fde3ac54700000000a3f3e44100000042ff1bc6f3
    fe3ef0010169897e400b000000006900a3be29a54fbc937a1dc1ad7e18bb300fcebaacfc08bb2461b7be2f4d4d3f1d5de63f2880c44700000000c95c6f4200000042ff1b6208
    fe3edf0101691ddb6d0700000000137787bc18d999bd9fdf1bc1e6c808bc053ae7ba77783a3b9b68643f5b45e93cc618e53f04f4c44700000000ced0214200000042ff1b128d
    fe3e9601016915bc6b0f00000000a8b4dabee9c755be4ffa1bc115ea92bc2e26bbbb482454bbb41e673fe1aea83eb158df3f9ebac44700000000be36484200000042ff1ba605
    fe3e4a0101690522c901000000001703e2bc63b32f3d552c1dc1cb4f023a5f3760bb9521753c8547673fd444d23cc6f3e43fa83bc5470000000010e5e34100000042ff1bd30d
    fe3eb301016988289c2200000000209ff3bd00ee25bee07522c1588413bd590218bd532e0fbddafe98be6ea85b3f25ede33fd8bac44700000000dd10484200000042ff1b0f9c
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








def infernmibound(txt):
    xs = intmsgs(txt)
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-1

    sigmas = []
    for i in range(max_k):
        ys = [x[i] for x in xs]
        zs = [x[i+1] for x in xs]

        H_ys = H(ys)
        H_zs = H(zs)
        nmi_v = NMI(ys,zs)
        print(i)
        print(" ",round(nmi_v,4),int(50*nmi_v)*"*")
        if nmi_v < .05 and (H_zs - H_ys) > 2:
            intervals = [INTERVAL("|",i+1,i+1) for x in xs]
            s = SIGMA([FIELD(intervals,valuescale=.1)])
            sigmas.append(s)
        #print(i,H_ys,H_zs)

        # are_ips = [isip(y) for y in ys]
        # #print(i,all(are_ips),ys)
        # if all(are_ips):
        #     intervals = [INTERVAL("I",i,i+4) for x in xs]
        #     s = SIGMA([FIELD(intervals,annotation="IP Address",valuescale=.1)])
        #     sigmas.append(s)
    print("NMIfinder found",sigmas)
    print(len(sigmas))
    if len(sigmas)==1:
        return sigmas[0]
    elif len(sigmas) == 0:
        return SIGMA([])
    else:
        return deconflict(sigmas)
if __name__ == "__main__":

    res = infernmibound(d1)
    print(res)
    print(res.apply(d1))

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")