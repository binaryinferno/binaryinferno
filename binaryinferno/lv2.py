

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

# Two byte length value pairs

from Weights import WCAT1
from Sigma import ascii2sigma,hexmsgs,msgs,SIGMA,FIELD,INTERVAL,UNIFY,mapUNIFY

def mklv(index):
  import random
  def v():
    return random.randrange(255,256)
  pref = [v() for i in range(index)]
  l = random.randrange(1,20)
  xs = [v() for i in range(l)]
  return bytes(pref+[l+index+1+4]+xs)

def mkds(index):
  if index > 0:
    s = "? L ?"
  else:
    s ="L ?"
  s+="\n--\n"
  for i in range(8):
    xs = mklv(index)
    pref = xs[:index]
    l = xs[index:index+1]
    suffix = xs[index+1:]
    s+= (pref.hex() + " " + l.hex() + " " +suffix.hex()+bytes([0,0,0,0]).hex()).strip()+"\n"
  s+="--"
  return s

def scrubds(txt):
  import re
  txt = re.sub('[ ]','',txt,flags=re.M)
  xs = txt.split("--")
  xs[0]="?\n"
  return "--".join(xs)

if False:
  print("-"*80)
  import random
  txt = mkds(random.choice([1,2,3]))
  print("Ground truth dataset")
  print(txt)
  print("")
  print("-"*80)
  print("Scrubbed of field boundaries")
  scrub = scrubds(txt)
  print(scrub)
  print("")
# print(hexmsgs(txt))
# s1 = ascii2sigma(txt)

# print(s1)

# print("")
# print(s1.apply(txt))

import struct
def inferlength2(txt,endian=">"):


  def diff(xs,ys):
    return [xs[i] - ys[i] for i in range(len(xs))]

  def slice(xs,i,k):

    if endian == ">":
      return [struct.unpack(endian+"I",bytes([0,0])+x[i:i+k])[0] for x in xs]
    else:
      return [struct.unpack(endian+"I",x[i:i+k]+bytes([0,0]))[0] for x in xs]

  xs = hexmsgs(txt)
  lines = msgs(txt)
  lens = [len(x) for x in xs]
  mml = min(lens)-1 #where's the last position we can handle

  valid = []
  diff_vals = []
  for i in range(mml):
    ys = slice(xs,i,2)  #how many bytes do we take
    #print("ys",ys)
    # Don't let them all be the same value
    if len(set(ys)) > 1:
      diffs = diff(lens,ys)
      #print("diffs",diffs)
      if len(list(set(diffs))) == 1:
        diff_val = list(set(diffs))
        diff_vals.append(diff_val)
        if diff_val[0] >=0:
          valid.append(i)
  #print(valid)
  sigs = []
  for j,i in enumerate(valid):
    #print("enumerave valid",j,i)
    if i > 0:
      s = "? L ?\n--\n"
    else:
      s = "L ?\n--\n"
    lines = [l[:i*2]+" "+l[i*2:(i*2)+2]+" "+l[(i*2)+2:] for l in lines]
    #return s + "\n".join(lines)+"\n--"
    intervals = [INTERVAL("L",i,i+2) for k in range(len(xs))]
    for k in range(len(xs)):
      intervals[k].width = len(xs[k])
    if endian == ">":
      end_anno = "BE"
    else:
      end_anno ="LE"
    sig = SIGMA([FIELD(intervals,annotation=end_anno+" uint16 Length +" + " " + str(diff_vals[j][0]) + " = Total Message Length",valuescale=WCAT1)])
    #print(sig)
    #print(sig.apply(txt))
    sigs.append(sig)
  for s in sigs:
    print(s)
  if len(sigs)>0:
    #print("sigs",sigs)
    return mapUNIFY(sigs)
  else:
    #return sigs[0]
    return SIGMA([])

def inferlength2BE(txt):
  return inferlength2(txt,endian=">")

def inferlength2LE(txt):
  return inferlength2(txt,endian="<")

if __name__ =="__main__":


  txt2 = """?
  --
  00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
  0000001e 0000 09f9 0304 7465 7374 1754 6869 7320 6973 2061 2074 6573 7420 6d65 7373 6167 6521
  00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
  00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
  --
  """
  inferlength4(txt2)

  foo = """
  00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
  0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
  00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
  00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21"""