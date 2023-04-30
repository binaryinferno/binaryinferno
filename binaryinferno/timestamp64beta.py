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

# Find timestamps of various types



from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from deconflict import deconflict


#fe3e00010169 19f84f1000000000 b55e97bd808c96b9cb0c1
#fe3e00010169 1a8aed0300000000 766cce3c99b937bdacbc1cc1e34

import datetime
import struct
import time
# bfh = bytes.fromhex("1a8aed0300000000")#("19f84f1000000000")
# recoverbinstamp = struct.unpack('<I', bfh[:4])[0]
# print(recoverbinstamp)
# tm = datetime.datetime.fromtimestamp(recoverbinstamp)
# print(tm)


# raw =   b'\x80\x57\x83\xa1\x64\xfa\xd4\x01'   # Python 2
# #raw = b'\x80\x57\x83\xa1\x64\xfa\xd4\x01'   # Python 3

# import struct
# unpacked, = struct.unpack('<Q', raw)
# print(unpacked)
# import datetime
# datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=unpacked/10.)

# tm =datetime.datetime.now()
# print(tm)
# tm = time.mktime(datetime.datetime.now().timetuple())
# print(tm)


# b = struct.pack('<Q',int(tm))
# print(b)
# unpacked, = struct.unpack('<Q', b)
# tm = datetime.datetime.fromtimestamp(unpacked) 
# print(tm)
# quit()
import random

fds = []
for i in range(10): 
    tm = time.mktime(datetime.datetime.now().timetuple())
    b = struct.pack('<Q',int(tm))
    m = [random.randrange(0,256) for x in range(8)] + [x for x in b] + [random.randrange(0,256) for x in range(8)]
    time.sleep(.5)
    fds.append(m)
    # unpacked, = struct.unpack('<Q', b)
    # tm = datetime.datetime.fromtimestamp(unpacked)

# 0  1  2  3  4  5 6  7  8  9  10 11 12 13 1415 1617 1819 2021 22
#fe 10 ca 01 01 6f 00 00 00 00 00 00 00 00 50d5 d7c4 7900 0000 f49e
d1 = """
?
--
fe3eb301016988289c2200000000209ff3bd00ee25bee07522c1588413bd590218bd532e0fbddafe98be6ea85b3f25ede33fd8bac44700000000dd10484200000042ff1b0f9c
fe3ea10101695debfb0b000000005ce0393d7799133db6b21cc1adf0c23dba31fc3c4079e33b4da098be3a44453f2212e93fd57ec447000000001140704200000042ff1b75c6
fe3edb010169d166620b0000000089cdbdbe2a4185bc4b7a1cc1ff83fc3ad7c72ebcf21ebb3b0be4b4beca774f3ff6dde43f157ec447000000003dbf704200000042ff1b74d1
fe3e00010169df6e7a0a00000000efa71ebebed28ebd22761cc1b54544bc7a78e83ba6923cbc9895bfbed89e513f6251e33fe27fc44700000000c88a6f4200000042ff1bc918
fe3e3801016979283e1b0000000073528ebef50491be113523c11fb1a9be339d1abfe243123f5518f1be43f76b3f1a8adb3fdabbc44700000000b263474200000042ff1b6c7b
fe3e1e01016926d5d40b00000000e85af63db31448bc25a51ec162568cbd9f742bbe1a74963a1e1c41bf069d2c3f3889dc3ffb7ec447000000000225704200000042ff1bb9e1
fe3e39010169de10810000000000e9c7833cf6d59f3d2c7c1cc1be61053cacfc133c637c45bbbfd1643fd000cd3c11c2e43fbd3ac54700000000ee1ee54100000042ff1ba9b4
fe3e0b0101692fd8e62000000000fa23aebee83b60bef03c1cc18b5a16bce453653c7429d5bb5906683ea18f613fa29fe43f34bbc44700000000a1d2474200000042ff1b138c
fe3e750101698a96d21e0000000028ff58be246d4fbe6fde1cc14a1aacbd7ce5ddbbfe6e26bba5afa23eabc15a3fc395e43fddbac44700000000280e484200000042ff1bca13
fe3e730101696ecc4506000000008c0dcb3cd22b253d437d1cc17f21babaf7c9233cb6f5f139b7af653f1a93133da528e53f0d3bc54700000000b3b2e44100000042ff1b8267
fe3e2b0101694dfa6e1a00000000724974beeeb662be3a5b1bc11d4277bc3d6baabdb60bc0bb487b46bfd17f8abe0022e93f1abbc44700000000dde2474200000042ff1b8ca5
fe3eab01016988f9b118000000002ee6b2bea00b47befd211cc1c6b430bb035b893c289175bbea9e49bfe86f78be28e4e93f7ebac44700000000634c484200000042ff1b467a
fe3e470101699b0fb32a00000000b8798a3b4e2743bd9f681cc13961a1bb97a267bceba6ee3bf94f683fab98353c65b2e33ff03bc54700000000a883e34100000042ff1bbca2
fe3edc01016901b2fb1c00000000f72535beccaca8be67521cc1ed48c63b779d243dcd39c73b53eb3fbf83d4c83e1e99e83ff9b9c44700000000ada5484200000042ff1b8a23
fe3e9e010169182146000000000065f19bbc68fd87bb3ed91cc1a31a343bba9c203c96398e3b1552663f372e033d25d6e43f7c3bc547000000009720e44100000042ff1be7d0
fe3ee501016952ce730b00000000fd2c4ebec2ba7fbdf3511cc1bb0b923b9207cf3b480d11bc861bb7be02d04e3f66a9e63f647ec44700000000d48b704200000042ff1b158a
fe3eaa01016935d11e0f000000000ea6abbe5c57babd74ec1cc1d05fe0bb9551ce3b1ce23fbbb5fa693f1c4aa43ef63ae03fe0bac44700000000730b484200000042ff1b0816
fe3e11010169fda33c050000000036dfef3c13f305bc94fa1bc12ffa283bee9f923bb0da3e3a5e91643f74dafc3ca009e43f5a3ac54700000000cea0e54100000042ff1b908e
fe3efc0101694890d20000000000a6a7063d373ee63cff291cc1bcd045bc2f1eeb3b56bbeabb6ae8653fe973c53c1b33e53f8a3ac54700000000de5fe54100000042ff1b56a9
fe3e660101692f88f521000000002c98bbbe04fb64be4c171dc194abbf3adaf58bbbcfb406bb42f16f3e8e19633fdabee23ffeb9c44700000000f9a2484200000042ff1b2cea
fe3e61010169976c9929000000007e4c2b3dea10fabc51f91cc162f92b3c1c13b6bc56fa88bb39fa643f92ba76bd49fde43fc008c5470000000096f5134200000042ff1b2c5b
fe3e5f01016999861c12000000009b0f91be130015beb1c31bc109832d3ce77cde3bb900e1bbc026203f017530bf162fe23f3dbac44700000000ae77484200000042ff1b86dc
fe3e72010169f769a2250000000023d799be46aa26be67571cc115d055bc76ed833cb73b6dbc6e09233f536a27bf13a3e43f1888c44700000000cd0b6a4200000042ff1b68fa
fe3e4f0101699aac460c0000000072e0af3d4f883abde9ff5ac075489a3da205103f9063553e2c6b10bf1e1b393f2ff1e33ffe7fc44700000000d8776f4200000042ff1b722f
fe3ef60101695861170500000000b14f633d608bd13b7cd31cc1e5bf5cbbdf3e433c3df6163b897c663f5303233d827ee43f053cc547000000009968e34100000042ff1b9118
fe3e880101695f3fae1d00000000385c2cbe7e807cbe5a3a1dc1b3526ebb9cf39f3abbf7df3b92c03dbf3ce8c13e7954e93f8cbac447000000004544484200000042ff1b7c19
fe3e17010169259ab70d000000008c3893bea8e31dbe7eb21dc198e99ebc0b0584ba1f39003b42bf653fb31d983e4d57e23f1dbbc44700000000dde2474200000042ff1b435f
fe3e370101696c88760b00000000b51337be799399bde0801dc1e25a29bbd8353b3dc5d5cd3acb10b4be30764f3ffa4de43f8b7fc447000000009ac36f4200000042ff1b5034
fe3eb501016924dfcb0f00000000c0d4a0bedb1e25bea1a31cc1539739ba17eba3bcd01ac5387c37623f0344ae3ebf14e13f81bac44700000000af49484200000042ff1ba291
fe3e0e0101696db5781200000000baedb7be80096bbe5d4f1dc171dc773c43962f3aa2fe17bb5b711b3f6a082fbfe565e43fecb9c44700000000cbad484200000042ff1bac99
fe3e46010169e2e9e9050000000008b7afbcf316f43c43a31dc1f5b1e4bbf2899c3b10bb7cbad0a7663fba23013d04afe43f463bc54700000000f066e44100000042ff1ba2a8
fe3eb40101695f91930500000000a5cccabc40d838bc68271dc1c1cc93bbd30b78bbe011b6b9820d693f4829f03cf530e63f4c3cc547000000003107e34100000042ff1bc192
fe3edc01016933deec2500000000c62199bed82f29be6e791cc19da68cbba22e3d3c2b335fbc0bce2c3fadb423bf129ae23f3588c44700000000dcf8694200000042ff1b7b3e
fe3eda0101693ad67e0c00000000abfca3be27f3ecbcf24d1ec182c1893dd54d5a3e02cf79bcd0a38f3f7639943eacbfd23fdf95c44700000000b2d1604200000042ff1be454
fe3e70010169ef01f51500000000770c85be1ee041be27ae1cc13e698a3b9ae3faba57d6b83b0bfb8bbe6b4853bf6af6e53f7db9c447000000008ef9484200000042ff1b2eb7
fe3e7301016904002f1e0000000070e415bedb1371beda791cc18a72c1bcf0358b3bdba6d2bbce6644bf02a8bc3e76f5e63ff4b9c4470000000062a8484200000042ff1bd449
fe3ee8010169bb255a0b000000007a1cc8bea269f9bc34711cc14c255539c5bb4bba30c290bbc179afbe9ba4503f00f9e63f667ec447000000001f89704200000042ff1b1437
fe3e850101695ec21d1200000000fa9aa4be200539be3e1d1dc1180ed93a6805bb3b53b7dbba2be01d3f77e52ebfde9be23fa0bbc447000000009389474200000042ff1b4623
fe3e7601016920f4110700000000941c873d107208bdb8bb09c197e40ebc4f4ac7bbf52f41bccfd6663f3f76f23cee67e43feb2fc547000000006094f34100000042ff1bea57
--"""

#00102030405060708090102030405060708090102030405
d12 = """
?
--
fe104801016f00000000000000005880a6aa710000000f23
fe107c01016f0000000000000000d02f08d78e0000002c5c
fe10fb01016f00000000000000005012a3c10b0000005641
fe107b01016f0000000000000000c00525086c00000077bf
fe104801016f0000000000000000d8841abb090000008319
fe109301016f0000000000000000505ee918680000001130
fe101601016f0000000000000000b841ae7e1a000000c569
fe10a101016f000000000000000040a639247a00000051dc
fe10c001016f000000000000000008d1a5b2640000008600
fe10b301016f0000000000000000a0aad30f360000000de7
fe108f01016f0000000000000000b875dc739500000057e4
fe101c01016f0000000000000000c826cd9e22000000a415
fe100b01016f00000000000000000004bf1522000000c211
fe10a101016f000000000000000068060abc340000004491
fe104501016f000000000000000050e4cbe78a00000039a5
fe102d01016f000000000000000030ad57556b00000013c8
fe101501016f0000000000000000581fdde7130000005f61
fe10ed01016f000000000000000088d893db9d0000009e0e
fe101901016f00000000000000006064d86e21000000c745
fe10b101016f0000000000000000f875a14c4e000000b9cc
fe107f01016f0000000000000000805f8970760000004bd4
fe101901016f0000000000000000f8698e884f00000073cb
fe108901016f000000000000000070d9233e81000000ca6c
fe100201016f0000000000000000600cadc84a000000c4a0
fe10e801016f00000000000000004033e2648b00000009f8
fe106b01016f0000000000000000d800bcec7300000055f8
fe106f01016f0000000000000000a8b9e53f5f000000ab2c
fe10f301016f0000000000000000f83d30821200000073c9
fe10ef01016f0000000000000000c0ad8008810000009e71
fe109601016f0000000000000000a81dc7a257000000ccd0
fe109801016f000000000000000040ef1b5f3c0000000d64
fe109501016f0000000000000000f877d9980e0000006d9c
fe109f01016f0000000000000000484fa766550000006811
fe108301016f000000000000000058d27df89a0000003786
fe100b01016f0000000000000000b8caf68d4d0000005617
fe102801016f0000000000000000c85cee99750000002947
fe104001016f0000000000000000b8476b53a00000001909
fe108801016f000000000000000058900dd3310000004d16
fe103d01016f0000000000000000f00d4e1c38000000ba42
fe107d01016f0000000000000000706414c71d00000009ff
fe10bb01016f000000000000000078a5e13502000000cab1
fe102b01016f00000000000000006097eb9c7f0000004af3
fe103901016f000000000000000098519cae2f000000a079
fe10ef01016f0000000000000000788f7bc80e000000b879--
"""
foo = """
Motivation:

An IP address should never start with 0
An IP Address should never end with 0
First Octet should be below 240"""


#
# import datetime
# import struct
# import time

# now = datetime.datetime.now()
# print now

# stamp = time.mktime(now.timetuple())
# print stamp

# recoverstamp = datetime.datetime.fromtimestamp(stamp)
# print recoverstamp

# binarydatetime = struct.pack('<L', stamp)
# recoverbinstamp = struct.unpack('<L', binarydatetime)[0]
# print recoverbinstamp

# recovernow = datetime.datetime.fromtimestamp(recoverbinstamp)
# print recovernow


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


from datetime import datetime
import statistics


# Should't see vertical slices of bytes with different entropy such as constant values or zeros in the interor
def hasstripes(xs):
    import re
    slices = [ [y[i]for y in xs] for i in range(len(xs[0]))]
    def isconst(xs):
        if len(set(xs))==1:
            return 'c'
        else:
            return 'n'

    s = "".join([isconst(x) for x in slices])
    s = re.sub('c+','c',s)
    s = re.sub('n+','n',s)
    
    #print(s)
    return "ncn" in s or "cn" in s or "cnc" in s


# def hasstripes(xs):
#     return False

def timestats(xs):
    min_t = min(xs)
    max_t = max(xs)
    span = max_t - min_t
    mean_t = int(sum(xs)/len(xs))
    return min_t,mean_t,max_t,span


def ns2s(x):
    return int(x/1000000000)

def ms2s(x):
    return int(x/1000000)

def allvalid(xs):
    v = 0
    for x in xs:
        try:
            datetime.fromtimestamp(x)
            v+=1
        except:
            pass

    return v/(1.0*len(xs))

def guess_ns(xs):
    s = [ns2s(x) for x in xs]
    #print("allvalid",allvalid(s))
    if allvalid(s) == 1.0:
        min_t,mean_t,max_t,span = timestats(s)
        #print("max_t",max_t,datetime.fromtimestamp(max_t))
        #print("mean_t",mean_t,datetime.fromtimestamp(mean_t))
        #print("min_t",min_t,datetime.fromtimestamp(min_t))
        start = datetime.fromtimestamp(0)
        days_from_epoch = (datetime.fromtimestamp(mean_t)-datetime.fromtimestamp(0)).days
        days_ago = (datetime.now()-datetime.fromtimestamp(mean_t)).days
        #print("mean",days_from_epoch)
        span_seconds = (datetime.fromtimestamp(max_t)-datetime.fromtimestamp(min_t)).seconds
        #print("span_secs",span_seconds)
        return ("ns","day_sago",days_ago,"mean",days_from_epoch,"span_secs",span_seconds)
    return ("allvalid",allvalid(s))

def allwithin(xs,dt,low,high):
    d = dt #datetime.fromtimestamp(dt)
    for x in xs:
        delta =  (datetime.fromtimestamp(x) - d)
        if delta.days > high or delta.days < low:
            return False
    return True


import math


def diverse(xs):
    return len(set(xs))/(1.0*len(xs)) >= .6


def guess_le_ms(xs_):

    
    xs = [struct.unpack('<Q', bytes(t))[0] for t in xs_]
    s = [ms2s(x) for x in xs]
    h_s =H(s)
    #print("allvalid",allvalid(s))
    if allvalid(s) == 1.0:
        min_t,mean_t,max_t,span = timestats(s)
        #print("max_t",max_t,datetime.fromtimestamp(max_t))
        #print("mean_t",mean_t,datetime.fromtimestamp(mean_t))
        #print("min_t",min_t,datetime.fromtimestamp(min_t))
        start = datetime.fromtimestamp(0)
        days_from_epoch = (datetime.fromtimestamp(mean_t)-datetime.fromtimestamp(0)).days
        days_ago = (datetime.now()-datetime.fromtimestamp(mean_t)).days
        #print("mean",days_from_epoch)
        span_seconds = (datetime.fromtimestamp(max_t)-datetime.fromtimestamp(min_t)).seconds
        #print("span_secs",span_seconds)

        all_near_epoch = allwithin(s,datetime.fromtimestamp(0),0,365)
        #all_near_epoch = False
        
        all_near_now = allwithin(s,datetime.now(),-365,7)
        #if days_from_epoch >= 0 and (days_from_epoch < 365 or days_from_epoch > 17000) and days_from_epoch < (datetime.now()-start).days+1:
        if not hasstripes(xs_) and (all_near_now or all_near_epoch) and h_s/(math.log(len(xs))/math.log(2))  > .5 :
            return ("ms","day_sago",days_ago,"Days From Epoch",days_from_epoch,"span_hrs",round((span_seconds/60.0/60.0),2),"all_near_epoch",all_near_epoch,"all_near_now",all_near_now,"H_s",h_s,math.log(len(xs))/math.log(2))
    return ("allvalid",allvalid(s))



def guess_le_s(xs_):
    xs = [struct.unpack('<I', bytes(t))[0] for t in xs_]
    s = xs

    h_s =H(s)
    #print("allvalid",allvalid(s))
    if allvalid(s) == 1.0:
        min_t,mean_t,max_t,span = timestats(s)
        #print("max_t",max_t,datetime.fromtimestamp(max_t))
        #print("mean_t",mean_t,datetime.fromtimestamp(mean_t))
        #print("min_t",min_t,datetime.fromtimestamp(min_t))
        start = datetime.fromtimestamp(0)
        days_from_epoch = (datetime.fromtimestamp(mean_t)-datetime.fromtimestamp(0)).days
        days_ago = (datetime.now()-datetime.fromtimestamp(mean_t)).days
        #print("mean",days_from_epoch)
        span_seconds = (datetime.fromtimestamp(max_t)-datetime.fromtimestamp(min_t)).seconds
        #print("span_secs",span_seconds)

        all_near_epoch = allwithin(s,datetime.fromtimestamp(0),0,365)
        #all_near_epoch = False
        
        all_near_now = allwithin(s,datetime.now(),-365,7)
        #print("near epoch",all_near_epoch,"near now",all_near_now)
        print("entropy",h_s/(math.log(len(xs))/math.log(2))  > .5,h_s/(math.log(len(xs))/math.log(2)),h_s,diverse(xs))
        #if days_from_epoch >= 0 and (days_from_epoch < 365 or days_from_epoch > 17000) and days_from_epoch < (datetime.now()-start).days+1:
        if not hasstripes(xs_) and (all_near_now or all_near_epoch) and h_s/(math.log(len(xs))/math.log(2))  > .5 :
            return ("s","day_sago",days_ago,"Days From Epoch",days_from_epoch,"span_hrs",round((span_seconds/60.0/60.0),2))
            return ("s","day_sago",days_ago,"Days From Epoch",days_from_epoch,"span_hrs",round((span_seconds/60.0/60.0),2),"all_near_epoch",all_near_epoch,"all_near_now",all_near_now,"H_s",h_s,math.log(len(xs))/math.log(2),"min_t",datetime.fromtimestamp(min_t),"max_t",datetime.fromtimestamp(max_t))

    return ("allvalid",allvalid(s))


VSCALE=.09

def infertsle64(txt,valuescale=VSCALE):
    xs = intmsgs(txt)
    #xs = fds
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml -7

    sigmas = []
    for i in range(max_k):
        tsb = [x[i:i+8] for x in xs]

        #ts = [struct.unpack('<Q', bytes(t))[0] for t in tsb]
        #print(ts[:3])

        # ts32 = [x[i:i+4] for x in xs]
        # ts32 = [struct.unpack('<I', bytes(t))[0] for t in ts32]
        
        if True:
            r = guess_le_ms(tsb)
            if r[0] != 'allvalid':
                print(i,"64",r)
                try:
                    for j in range(5):
                        print("\t",bytes(tsb[j]).hex())
                except:
                    pass
                intervals = [INTERVAL("T",i,i+8) for x in xs]
                s = SIGMA([FIELD(intervals,annotation="LE Timestamp 64",valuescale=valuescale)])
                sigmas.append(s)
                #print(i,"32",guess_s(ts32))


    print("TS64 found",sigmas)
    print(len(sigmas))
    if len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas



def infertsbe64(txt,valuescale=VSCALE,span=None):
    xs = intmsgs(txt)
    #xs = [x[::-1] for x in xs]
    #xs = fds
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml -7

    sigmas = []
    for i in range(max_k):
        tsb = [x[i:i+8][::-1] for x in xs]

        #ts = [struct.unpack('<Q', bytes(t))[0] for t in tsb]
        #print(ts[:3])

        # ts32 = [x[i:i+4] for x in xs]
        # ts32 = [struct.unpack('<I', bytes(t))[0] for t in ts32]
        
        if True:
            r = guess_le_ms(tsb)
            if r[0] != 'allvalid':
                print(i,"64",r)
                # for j in range(5):
                #     print("\t",bytes(tsb[j]).hex())

                intervals = [INTERVAL("T",i,i+8) for x in xs]
                s = SIGMA([FIELD(intervals,annotation="BE Timestamp 64",valuescale=valuescale)])
                sigmas.append(s)
                #print(i,"32",guess_s(ts32))


    print("TS64 found",sigmas)
    print(len(sigmas))
    if len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas




def infertsle32(txt,valuescale=VSCALE):
    xs = intmsgs(txt)
    #xs = fds
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml -3

    sigmas = []
    for i in range(max_k):
        tsb = [x[i:i+4] for x in xs]

        #ts = [struct.unpack('<Q', bytes(t))[0] for t in tsb]
        #print(ts[:3])

        # ts32 = [x[i:i+4] for x in xs]
        # ts32 = [struct.unpack('<I', bytes(t))[0] for t in ts32]
        
        if True:
            r = guess_le_s(tsb)
            if r[0] != 'allvalid':
                print(i,"32",r)
                for j in range(3):
                    print("\t",bytes(tsb[j]).hex())

                intervals = [INTERVAL("T",i,i+4) for x in xs]
                s = SIGMA([FIELD(intervals,annotation="LE Timestamp 32" + " " + str(r),valuescale=valuescale)])
                sigmas.append(s)
                #print(i,"32",guess_s(ts32))



    print("TS32 found",sigmas)
    print(len(sigmas))
    if len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas

def infertsbe32(txt,valuescale=VSCALE):
    xs = intmsgs(txt)
    #xs = [x[::-1] for x in xs]
    #xs = fds
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml -3

    sigmas = []
    for i in range(max_k):
        tsb = [x[i:i+4][::-1] for x in xs]

        #ts = [struct.unpack('<Q', bytes(t))[0] for t in tsb]
        #print(ts[:3])

        # ts32 = [x[i:i+4] for x in xs]
        # ts32 = [struct.unpack('<I', bytes(t))[0] for t in ts32]
        
        if True:
            r = guess_le_s(tsb)
            #print(i,r)
            if r[0] != 'allvalid':
                # print(i,"32",r)
                # for j in range(5):
                #     print("\t",bytes(tsb[j]).hex())

                intervals = [INTERVAL("T",i,i+4) for x in xs]
                s = SIGMA([FIELD(intervals,annotation="BE Timestamp 32"+ " " + str(r),valuescale=valuescale)])
                sigmas.append(s)
                #print(i,"32",guess_s(ts32))



    print("TS32 found",sigmas)
    print(len(sigmas))
    if len(sigmas) == 0:
        return [SIGMA([])]
    else:
        return sigmas

if __name__ == "__main__":

    #print(infertsle64(d12))
    dtsbe32="""
    ?
    --
    000000c10008ff364237a502c2f3967e
0000017c0008fe7b42390d2cc2e351ba
000000580008ff9f42426b45c2f249ae
0000015d0008fe9a4237e120c2e42626
000000680008ff8f42406b00c2ef713f
000000a20008ff554233cd87c2f3cf33
0000036b0008fc8c422866d3c2e9071b
0000035a0008fc9d422668eac2ec399f
0000023e0008fdb94237e30dc2e7ce61
000001d20008fe2542405119c2e9c690
000002df0008fd184229b42bc2f85d1c
000003520008fca54226dd96c2ef85fc
000001cc0008fe2b42401a1dc2e4de8e
000003290008fcce4224fbdac2ef6908
000002d20008fd254229d3d4c2f6455e
0000004c0008ffab4241cd0dc2f0d03a
000003210008fcd6422640dcc2eba4b5
000003e00008fc174224309ec2f26080
--""" 

    dtsbe32="""?
--60008ab1
60008ab1
60008ab2
60008ab2
60008ab3
60008ab3
60008ab4
60008ab4
60008ab4
60008ab4
60008ab5
60008ab5
60008ab5
60008ab6
60008ab6
60008ab6
60008ab7
60008ab7
60008ab8
60008ab8
60008ab9
60008ab9
60008aba
60008aba
60008abb
60008abb
60008abb
60008abc
60008abd
60008abd
60008abe
60008abf
60008ac0
60008ac1
60008ac1
60008ac1
60008ac1
60008ac2
60008ac2
60008ac2
60008ac3
60008ac3
60008ac3
60008ac3
60008ac3
60008ac3
60008ac4
60008ac4
60008ac4
60008ac5
60008ac6
60008ac6
60008ac7
60008ac8
60008ac9
60008ac9
60008ac9
60008aca
60008acb
60008acc
60008acc
60008acd
60008ace
60008acf
60008ad0
60008ad0
60008ad1
60008ad1
60008ad2
60008ad3
60008ad4
60008ad4
60008ad5
60008ad6
60008ad7
60008ad8
60008ad9
60008ad9
60008ada
60008ada
60008ada
60008ada
60008adb
60008adb
60008adc
60008add
60008ade
60008adf
60008adf
60008adf
60008adf
60008ae0
60008ae0
60008ae1
60008ae2
60008ae3
60008ae4
60008ae4
60008ae4
60008ae4
--"""
    print(infertsbe32(dtsbe32))

    # xs = [[0,10,0,0,1,27],[0,192,168,0,55,99]]
    # print(isip([10,0,0,1]))


    # print("")