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
#

# Is some data floats or not?


from Samples import sliceDataset, makeSamples
import random
import struct
import pickle


def mksomedata():
    val = []

    for i in range(10):

        x = random.randrange(0,200)+random.random()
        xb = [j for j in struct.pack("<f",x)]
        #xb = struct.pack("<f",x)
        #v = bytes([0,0,0,0]+xb+ [random.randrange(0,256) for i in range(4)]+xb)
        v = bytes( xb)
        #print(i,v)
        val.append(v)

    random.shuffle(val)
    return val


# Is this a set of data a float or not?
def predictfloat(xs,LE=True):
    #tds = sliceDataset(WINDOW,xs,gt)
    tds = sliceDataset(4,xs,[0,1,2,3])
    ds = tds[0]
    dims = ds["dims"]

    try:
         if dims["f_var"] > 100000:
            return False
    except:
        pass
    # Used to debug float dimensions
    # for d in dims:
    #     print("floatdims",d,dims[d])

    return  dims["b1_allsame"] == 0 and dims["b2_allsame"] == 0 and dims["b3_allsame"] == 0 and dims["lshape"]>.42 and dims["lshape"] <.55

    #return dims["b0_allsame"] == 0 and dims["b1_allsame"] == 0 and dims["b2_allsame"] == 0 and dims["b3_allsame"] == 0 and dims["lshape"]>.42 and dims["lshape"] <.55

def loadDataset(fname):
    f = open(fname, 'rb') 
    # The protocol version used is detected automatically, so we do not
    # have to specify it.
    dataset = pickle.load(f)
    f.close()

    return dataset

    #labels = sorted([k for k in dataset[0]["dims"]])




def unittest():
    from collections import Counter
    q = Counter()
    wdbc_ds = loadDataset("int_wdbc_dataset_full.pkl")#"/data/chandler/int_ion_dataset_full.pkl")
    for d in wdbc_ds:

        dims = d["dims"]

        gt = bool(d["gt"])
        predict = dims["b0_allsame"] == 0 and dims["b1_allsame"] == 0 and dims["b2_allsame"] == 0 and dims["b3_allsame"] == 0 and dims["lshape"]>.42 and dims["lshape"] <.55
        #print(d["gt2"],d["gt"],)
        q[(gt,predict)]+=1

    print("Truth, Prediction")
    for r in q:
        print(r,q[r])


if __name__ == '__main__':
    
    
    unittest()
    print("")

    # We pass the predictor a list of 4-byte candidate floats
    xs = mksomedata()
    print("messages",xs)
    # It generates the features and evaluates
    res = predictfloat(xs)
    print("Are these floats?:",res)