

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

# Are these Length Value Pairs?

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
from sklearn.metrics.cluster import normalized_mutual_info_score
NMI = normalized_mutual_info_score
from  scipy.stats import pearsonr

def fuzzylength(field,lens):

  #print(field,lens)
  if len(set(field)) == 1:
    return False

  # We want high nmi
  nmi_v = NMI(lens,field)

  # Must lens must be strictly >= field
  sats = all([field[i] <= v for i,v in enumerate(lens)])

  # Must be correlated
  r = pearsonr(lens,field)
  r = r[0] 

  return nmi_v == 1 and sats and r > .95

def inferlength(txt):


  def diff(xs,ys):
    return [xs[i] - ys[i] for i in range(len(xs))]

  def slice(xs,i):
    return [x[i] for x in xs]

  xs = hexmsgs(txt)
  lines = msgs(txt)
  lens = [len(x) for x in xs]
  mml = min(lens)

  valid = []
  fuzzy_valid = []
  diff_vals = []
  for i in range(mml):
    ys = slice(xs,i)
    # Don't let them all be the same value
    if len(set(ys)) > 1:
      diffs = diff(lens,ys)

      # If uniform offset from end
      if len(list(set(diffs))) == 1:
        diff_val = list(set(diffs))
        diff_vals.append(diff_val)
        if diff_val[0] >=0:
          valid.append(i)
        else:
          #Diff wasn't positive
          pass
      else:
        # Multiple diff values, so no gucci

        # Lets not be too hasty, try a fuzzy match
        fz = fuzzylength(ys,lens)
        if fz:
          fuzzy_valid.append(i)
        else:
          # Couldn't make it work even while fuzzy
          pass
    else:
      # Candidate length field was of a single lenght value
      pass

  # Build sigmas for regular length fields
  sigs = []
  for j,i in enumerate(valid):
    if i > 0:
      s = "? L ?\n--\n"
    else:
      s = "L ?\n--\n"
    lines = [l[:i*2]+" "+l[i*2:(i*2)+2]+" "+l[(i*2)+2:] for l in lines]
    #return s + "\n".join(lines)+"\n--"
    intervals = [INTERVAL("L",i,i+1) for k in range(len(xs))]
    for k in range(len(xs)):
      intervals[k].width = len(xs[k])
    sig = SIGMA([FIELD(intervals,annotation="Length +" + " " + str(diff_vals[j][0]) + " = Total Message Length",valuescale=WCAT1)])
    #print(sig)
    #print(sig.apply(txt))
    sigs.append(sig)

  for j,i in enumerate(fuzzy_valid):
    if i > 0:
      s = "? L ?\n--\n"
    else:
      s = "L ?\n--\n"
    lines = [l[:i*2]+" "+l[i*2:(i*2)+2]+" "+l[(i*2)+2:] for l in lines]
    #return s + "\n".join(lines)+"\n--"
    intervals = [INTERVAL("L",i,i+1) for k in range(len(xs))]
    for k in range(len(xs)):
      intervals[k].width = len(xs[k])
    sig = SIGMA([FIELD(intervals,annotation="Fuzzy Length <= Real Length",valuescale=WCAT1)])
    #print(sig)
    #print(sig.apply(txt))
    sigs.append(sig)

  if len(sigs)>0:
    #print("sigs",sigs)
    return mapUNIFY(sigs)
  else:
    #return sigs[0]
    return SIGMA([])

if __name__ =="__main__":
  print("-"*80)
  print("Inferred")
  print("")
  ftxt = inferlength(scrub)
  #print(ftxt)
  print("xxxx")

  txt2 = """?
  --
  00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
  0000001e 0000 09f9 0304 7465 7374 1754 6869 7320 6973 2061 2074 6573 7420 6d65 7373 6167 6521
  00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
  00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
  --
  """
  inferlength(txt2)

  foo = """
  00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
  0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
  00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
  00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21"""