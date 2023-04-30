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

# Timestamp inference


import sys
import datetime
import struct
import time
from collections import Counter
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL
from datetime import timezone, datetime, timedelta
import datetime
from hasstripes import hasstripes


VSCALE=.95
from Weights import WCAT2
VSCALE=WCAT2

# d = datetime(2009, 4, 19, 21, 12, tzinfo=timezone(timedelta(hours=-2)))
# d.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')


# # d23cfacdd0e699f7
# def bytes2ts(b):
#   # unpack as Big Endian
#   unpacked, = struct.unpack('<Q', b)
#   print(b)
#   unpacked = int(unpacked/1000000)
#   print(unpacked)

#   tm =datetime.datetime.fromtimestamp(unpacked) 
#   return tm

# def bytes2ts(b,ENDIAN=">",EPOCH_DELTA=0):
#   qs,  = struct.unpack(ENDIAN+"I",b[:4])
#   #qs = time.ctime(qs)

    
#   raw_tm = datetime.datetime.fromtimestamp(qs-EPOCH_DELTA)
#   #tm = raw_tm-EPOCH_DELTA
#   return raw_tm


# def predictts(bs,low,high,ENDIAN=">",EPOCH_DELTA=0):
#   pass
# def main(data,low,high):
#   print(low,bytes2ts(low))
#   print(high,bytes2ts(high))

#   for d in data[:10]:
#       print(d,bytes2ts(d))


# def predict(bs,low_epoch_int,high_epoch_int,ENDIAN=">",EPOCH_DELTA=0):
#   for b in bs:
#       b_int, = struct.unpack(">I",d[:4])
#       b_int = int(b_int - EPOCH_DELTA)
#       print(low_epoch_int,b_int,high_epoch_int)
#   pass


def lowhigh2epochlowhigh(low_str,high_str):
    epoch_str = '1970-01-01 00:00:00.000000'
    #date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S.%f')


    low_epoch = datetime.datetime.strptime(low_str, '%Y-%m-%d %H:%M:%S.%f')
    high_epoch = datetime.datetime.strptime(high_str, '%Y-%m-%d %H:%M:%S.%f')
    unix_epoch = datetime.datetime.strptime(epoch_str, '%Y-%m-%d %H:%M:%S.%f')

    # Calculate our lower boundary in second from unix epoch
    low_secs = int((low_epoch-unix_epoch).total_seconds())
    # Calculate our upper boundary in seconds from unix epoch 
    high_secs = int((high_epoch-unix_epoch).total_seconds()) 

    # Don'e use this byt we could
    span_secs = high_secs - low_secs



    return (unix_epoch,unix_epoch+datetime.timedelta(0,span_secs))

# Get the number of seconds between classic unix epoch and our chosen start of time
# We use this to adjust the data values to see if they are in the 
# range of our low and high timestamps
def epoch_delta_seconds(epoch_string):
    unix_epoch_string = "01/01/1970"
    unix_element = datetime.datetime.strptime(unix_epoch_string,"%d/%m/%Y")

    ntp_element = datetime.datetime.strptime(epoch_string,"%d/%m/%Y")
    delta_element = unix_element-ntp_element
    delta_seconds = int((delta_element).total_seconds())
    return delta_seconds


NTP_delta_seconds = 2208988800
NTP_delta_seconds = epoch_delta_seconds("01/01/1900")

# Given a list of bytes say whether this is a set of timestamps
# low_str = timestamp string for low bound: 1970-01-01 00:00:00.000000
# high_str = timestamp string for high bound
# Base these bounds around when the sample was collected
# Endian = the format of the data
# Epoch_offset = number of seconds difference between 1/1/1970 and the assumed epoch
# We adjust the data by this many seconds before checking that it fits between hi and low
# Slop = how much time before low and after high we want to include
# This allows us to account for things like GMT, weird Timezones, etc
# Scale is how much we need to divide the seconds portion of the data by
# For example if the time_stamp is in microseconds (millions of a second)
# Then dividing the value by the scale will get us the time in seconds from epoch

def predictts(bs,low_str,high_str,ENDIAN=">I",EPOCH_OFFSET=0,SLOP=24*60*60,SCALE=1.0):

    
    epoch_str = '1970-01-01 00:00:00.000000'
    #date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S.%f')


    low_epoch = datetime.datetime.strptime(low_str, '%Y-%m-%d %H:%M:%S.%f')
    high_epoch = datetime.datetime.strptime(high_str, '%Y-%m-%d %H:%M:%S.%f')
    unix_epoch = datetime.datetime.strptime(epoch_str, '%Y-%m-%d %H:%M:%S.%f')

    # Calculate our lower boundary in second from unix epoch
    low_secs = int((low_epoch-unix_epoch).total_seconds())
    # Calculate our upper boundary in seconds from unix epoch 
    high_secs = int((high_epoch-unix_epoch).total_seconds()) 

    # Don'e use this byt we could
    span_secs = high_secs - low_secs

    # Adjust bounds with slop
    low_secs-=SLOP
    high_secs+=SLOP

    # Check for stripes

    if ">" in ENDIAN:
        # Big
        if hasstripes(bs,"BE"):
            print("\tHas BE stripes")
            return 0.0
    else:
        # little
        if hasstripes(bs,"LE"):
            print("\tHas LE stripes")
            return 0.0

    # Interpret byte values as seconds
    def interpret(bs):
        # bs are byte list
        vs = []
        outcomes = []
        tot = 0
        qty_zero = 0
        for b in bs:
            
            d_int, = struct.unpack(ENDIAN,b)
            #print("dint",d_int)
            # if d_int == 0:
            #     qty_zero+=1
            #     continue
            # else:
            #     tot+=1
            # scale into seconds, adjust by epoch_offset 
            d_secs = int(d_int/SCALE) - EPOCH_OFFSET

            # Keep the values in case we need them
            vs.append(d_secs)
            if False:
                print(low_secs,d_secs,high_secs,low_secs<=d_secs and d_secs<= high_secs)

            # Test that value is greater than the low and less than the high
            outcomes.append(low_secs<=d_secs and d_secs<= high_secs)

        data_range = max(vs)-min(vs)

        # Count true and false cases
        q = Counter(outcomes)
        if False:
            print(Counter(outcomes),"data range",data_range,"guard range",span_secs)

        # Return percentage where true
        return q[True]/(len(bs))

    res = interpret(bs)
    return res



# Seconds + Microseconds + OFFSET
def BE_TS64_SUS_NTPPURE(data,low_str,high_str):
    # low_str = '2011-10-10 02:03:26.000000'
    # high_str = '2011-10-10 02:07:26.000000'
    data = [d[:4] for d in data]



    return predictts(data,low_str,high_str,ENDIAN=">I",EPOCH_OFFSET=NTP_delta_seconds)

# Seconds + Microseconds + OFFSET
def BE_TS64_SUS_NTP(data,low_str,high_str):
    # low_str = '2011-10-10 02:03:26.000000'
    # high_str = '2011-10-10 02:07:26.000000'
    trimdata = [d[:4] for d in data]

    filtereddata = [d[:4] for d in data if d != bytes([0,0,0,0,0,0,0,0])]

    perczeros = [d for d in data if d == bytes([0,0,0,0,0,0,0,0])]
    #print("perczeros",len(perczeros),len(data),data[0])

    if len(perczeros)/len(data) < .5:
        data = filtereddata
    else:
        data = trimdata

    return predictts(data,low_str,high_str,ENDIAN=">I",EPOCH_OFFSET=NTP_delta_seconds)

# Mavlink
# Microseconds
def LE_TS64_US(data,low_str,high_str):
    # low_str = '1970-01-01 00:00:00.000000'
    # high_str = '1970-01-01 00:04:00.000000'
    return predictts(data,low_str,high_str,ENDIAN="<Q",EPOCH_OFFSET=0,SCALE=1000000.0)

def BE_TS64_US(data,low_str,high_str):
    # low_str = '1970-01-01 00:00:00.000000'
    # high_str = '1970-01-01 00:04:00.000000'
    return predictts(data,low_str,high_str,ENDIAN=">Q",EPOCH_OFFSET=0,SCALE=1000000.0)

#Seconds
def LE_TS32_S(data,low_str,high_str):
    # low_str = '1970-01-01 00:00:00.000000'
    # high_str = '1970-01-01 00:04:00.000000'
    # data = [d[:4] for d in data]
    return predictts(data,low_str,high_str,ENDIAN="<I",EPOCH_OFFSET=0)

#Seconds
def BE_TS32_S(data,low_str,high_str):
    #data = [d[:4] for d in data]
    return predictts(data,low_str,high_str,ENDIAN=">I",EPOCH_OFFSET=0)





def TS32_S(data,low_str,high_str,ENDIAN=">I",EPOCH_OFFSET=0,SLOP=24*60*60,SCALE=1.0):
    return predictts(data,low_str,high_str,ENDIAN=ENDIAN,EPOCH_OFFSET=EPOCH_OFFSET,SLOP=SLOP,SCALE=SCALE)

def TS64_US(data,low_str,high_str,ENDIAN=">Q",EPOCH_OFFSET=0,SLOP=24*60*60,SCALE=1000000.0):
    return predictts(data,low_str,high_str,ENDIAN=ENDIAN,EPOCH_OFFSET=EPOCH_OFFSET,SLOP=SLOP,SCALE=SCALE)




def search(txt,f,annotation,valuescale,BYTES):
    # make em int lists
    xs = intmsgs(txt)
    n = len(xs)

    lens = [len(x) for x in xs]
    mml = min(lens)

    # How close to the edge can we go?
    max_k = mml -(BYTES-1)

    sigmas = []
    for i in range(max_k):
        print("\tconsidering i",i)
        # Make it a byte list
        tsb = [bytes(x[i:i+BYTES]) for x in xs]
        # invoke the function
        r = f(tsb)
        #no_stripes 
        print("\tr val",r)
        if r>=.99:
            print(i,r,annotation)
            intervals = [INTERVAL("T",i,i+BYTES) for x in xs]
            s = SIGMA([FIELD(intervals,annotation=annotation+ " " + str(r) ,valuescale=valuescale)])
            sigmas.append(s)
    print("sigmas",sigmas)
    return sigmas

def search64bit(txt,f,annotation="Timestamp 64",valuescale=VSCALE):
    r = search(txt,f,annotation,valuescale,8)
    return r

def search32bit(txt,f,annotation="Timestamp 32",valuescale=VSCALE):
    return search(txt,f,annotation,valuescale,4)




def infertsbe32(txt,valuescale=VSCALE):
    xs = intmsgs(txt)
    #xs = [x[::-1] for x in xs]
    #xs = fds
    n = len(xs)


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml -7

    sigmas = []
    for i in range(max_k):
        tsb = [x[i:i+4][::-1] for x in xs]
        tsb = [bytes(x[i:i+4]) for x in xs]

        r = LE_TS64_US_EPOCH(tsb)
        print(r)
        for t in tsb[:5]:
            print("\t",i,"\t",t.hex())


    return None

    if False:
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


def mk_ts_functions(low_str,high_str):
    els,ehs= lowhigh2epochlowhigh(low_str,high_str)
    els2= str(els)+".000000"
    ehs2= str(ehs)+".000000"
    epoch_low_str =  els2 #'1970-01-01 00:00:00.000000'
    epoch_high_str = ehs2 #'1970-01-01 00:04:00.000000'

    LE_TS64_US_EPOCH = lambda data: LE_TS64_US(data,epoch_low_str,epoch_high_str)
    LE_TS64_US_SPAN = lambda data: LE_TS64_US(data,low_str,high_str)
    LE_TS32_S_EPOCH = lambda data: LE_TS32_S(data,epoch_low_str,epoch_high_str)
    LE_TS32_S_SPAN = lambda data: LE_TS32_S(data,low_str,high_str)

    BE_TS64_SUS_NTP_SPAN = lambda data: BE_TS64_SUS_NTP(data,low_str,high_str)
    BE_TS64_SUS_NTPPURE_SPAN = lambda data: BE_TS64_SUS_NTPPURE(data,low_str,high_str)

    BE_TS64_US_EPOCH = lambda data: BE_TS64_US(data,epoch_low_str,epoch_high_str)
    BE_TS64_US_SPAN = lambda data: BE_TS64_US(data,low_str,high_str)
    BE_TS32_S_EPOCH = lambda data: BE_TS32_S(data,epoch_low_str,epoch_high_str)
    BE_TS32_S_SPAN = lambda data: BE_TS32_S(data,low_str,high_str)

    TXT_EPOCH = " " + epoch_low_str + " to " +epoch_high_str
    TXT_SPAN = " " + low_str + " to " +high_str

    tsf1 =("LE_64BIT_EPOCH_Microseconds_LE",lambda data: search64bit(data,LE_TS64_US_EPOCH,"LE 64BIT EPOCH Microseconds" + TXT_EPOCH))
    tsf2 =("LE_64BIT_SPAN_Microseconds_LE", lambda data: search64bit(data,LE_TS64_US_SPAN,"LE 64BIT SPAN Microseconds" + TXT_SPAN))
    tsf3 =("LE_32BIT_EPOCH_Seconds_LE",lambda data: search32bit(data,LE_TS32_S_EPOCH,"LE 32BIT EPOCH Seconds" + TXT_EPOCH))
    tsf4 =("LE_32BIT_SPAN_Seconds_LE",lambda data: search32bit(data,LE_TS32_S_SPAN,"LE 32BIT SPAN Seconds" + TXT_SPAN))

    tsf5 =("BE_64BIT_NTP_SPAN_Microseconds_BE",lambda data: search64bit(data,BE_TS64_SUS_NTP_SPAN,"BE 64BIT NTP SPAN Microseconds" + TXT_SPAN))
    tsf5a =("BE_64BIT_NTPPURE_SPAN_Microseconds_BE",lambda data: search64bit(data,BE_TS64_SUS_NTPPURE_SPAN,"BE 64BIT NTP SPAN Microseconds (No Null Values)" + TXT_SPAN))

    tsf6 =("BE_64BIT_EPOCH_Microseconds_BE",lambda data: search64bit(data,BE_TS64_US_EPOCH,"BE 64BIT EPOCH Microseconds" + TXT_EPOCH))
    tsf7 =("BE_64BIT_SPAN_Microseconds_BE", lambda data: search64bit(data,BE_TS64_US_SPAN,"BE 64BIT SPAN Microseconds" + TXT_SPAN))
    tsf8 =("BE_32BIT_EPOCH_Seconds_BE",lambda data: search32bit(data,BE_TS32_S_EPOCH,"BE 32BIT EPOCH Seconds" + TXT_EPOCH))
    tsf9 =("BE_32BIT_SPAN_Seconds_BE",lambda data: search32bit(data,BE_TS32_S_SPAN,"BE 32BIT SPAN Seconds" + TXT_SPAN))

    return [tsf2,tsf4,tsf5,tsf5a,tsf7,tsf9]
    return [tsf1,tsf2,tsf3,tsf4,tsf5,tsf6,tsf7,tsf8,tsf9]
if __name__ == '__main__':


    import time
    import datetime
      

    sigmas = []


    data = sys.stdin.read().strip()
    if "--" not in data:
        data = "--\n"+data+"\n--"

    low_str = '2021-05-05 00:00:00.000000'
    high_str = '2021-05-06 00:04:00.000000'

    els,ehs= lowhigh2epochlowhigh(low_str,high_str)
    print(els,ehs)
    els2= str(els)+".000000"
    ehs2= str(ehs)+".000000"
    print(str(els2),str(ehs2))
    epoch_low_str =  els2 #'1970-01-01 00:00:00.000000'
    epoch_high_str = ehs2 #'1970-01-01 00:04:00.000000'


    LE_TS64_US_EPOCH = lambda data: LE_TS64_US(data,epoch_low_str,epoch_high_str)
    LE_TS64_US_SPAN = lambda data: LE_TS64_US(data,low_str,high_str)
    LE_TS32_S_EPOCH = lambda data: LE_TS32_S(data,epoch_low_str,epoch_high_str)
    LE_TS32_S_SPAN = lambda data: LE_TS32_S(data,low_str,high_str)

    sigmas+=search64bit(data,LE_TS64_US_EPOCH,"LE 64BIT EPOCH Microseconds")
    sigmas+=search64bit(data,LE_TS64_US_SPAN,"LE 64BIT SPAN Microseconds")
    sigmas+=search32bit(data,LE_TS32_S_EPOCH,"LE 32BIT EPOCH Seconds")
    sigmas+=search32bit(data,LE_TS32_S_SPAN,"LE 32BIT SPAN Seconds")

    # data = [bytes.fromhex(line.strip()) for line in data.split("\n")]

    print("-"*80)
    for s in sigmas:
        print(s)

    print("\n\n")
    print("-"*80)

    low_str = '2011-10-10 00:00:00.000000'
    high_str = '2011-10-12 00:04:00.000000'
    fs = mk_ts_functions(low_str,high_str)
    for l,f in fs:
        print(l)
        for s in f(data):
            print("\t",s)
    quit()




    # TS32_S_BE = lambda: data,low,high: TS_


    # BE_TS64_NTP(data)
    # print("xx")
    # LE_TS64_EPOCH(data)
    # print("xx")
    # LE_TS32_EPOCH([struct.pack("<I",i) for i in range(0,10000,100)])

    data = []
    base = int(time.time())
    data = []
    import random
    for i in range(20):
        data.append(struct.pack(">I",base))
        base+=random.randrange(0,45)

    v= BE_TS32_S_EPOCH(data,low_str,high_str)
    print(v)
    # ssss.mmmm
    # 

    # s = "d23cfacdd0e699f7"
    # print("s",s)
    # h = bytes.fromhex(s)





    # ---------------------------------------------------------------------------------------


