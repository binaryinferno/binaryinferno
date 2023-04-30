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

# This file is where we define the intermediate representation of our hypothesis. 

# ------------------------------------------------------------------------------------------------------------------------------------------------
# IR 
# ------------------------------------------------------------------------------------------------------------------------------------------------



import re

# Break some ASCII data into 3 chunks
def parts(xs):
  xs = "\n".join([x for x in xs.split("\n") if ((len(x) > 0 and x[0] != "#"))])
  xs = [x.strip() for x in xs.split("--")]

  header,data,trailer = xs
  return (header,data,trailer)


# Turn data into list of intervals
def intervalizeline(xs,header):

  # Collapse repeated tabs and spaces
  xs = re.sub('[ \t]+',' ',xs,flags=re.M)

  # Break a line into chunks based on space delimiters
  xs = xs.split(" ")

  # Muy importante
  xs = [bytes.fromhex(m) for m in xs] #Turn it into hex
  res = []
  start = 0
  end = 0
  field_id = 0
  for x in xs:

    # Find the label for this field from the header. 
    # Use that as the type for the interval
    ty = header[field_id]

    # We use the | character to indicate a zero width boundary
    if x == "|":
      end = start
      v = {'ty':ty,'field_id':field_id,'start':start,'stop':end,'val':x}
      res.append(v)
    else:
      end = start + len(x)
      v = {'ty':ty,'field_id':field_id,'start':start,'stop':end,'val':x}
      res.append(v)
    start = end
    field_id+=1
  return res


# Turn rows into list of interval lists
def intervalizerows(xs,header):
  xs =xs.strip().split("\n")
  res = []
  for x in xs:
     res.append(intervalizeline(x,header))
  return res

# Get the header fields from an ascii rep
def parseheader(header):
  header = re.sub('[ \t]+',' ',header.strip(),flags=re.DOTALL)
  header_fields = header.split(" ")

  # Just use the first chracter as a key
  header_fields = [x[0] for x in header_fields]
  return header_fields


# Parse the trailer. 
# We will use this in the future to collect facts about the fields
def parsetrailer(trailer):
  trailer = trailer.strip()
  field_types = [x.strip() for x in trailer.split("\n")]
  for x in field_types:
    pass


# from Sigma import FIELD,INTERVAL,SIGMA
def bytes2ascii(xs):
  s = "?\n--\n"
  s+="\n".join([x.hex() for x in xs]) + "\n--"
  return s

# Given some ascii data 
def ascii2sigma(txt):
 
  # break ASCII into parts
  header,data,trailer = parts(txt)

  header = parseheader(header)

  # turn the data into rows of intervals
  rows = intervalizerows(data,header)

  from collections import defaultdict
  dd = defaultdict(lambda:[])

  # for each row of intervals 
  for r in rows:
    # group the intervals together 
    for interval in r:
      field_id = interval['field_id']
      dd[field_id].append(interval)


  # turn groups of intervals into fields
  fields = []
  for key in dd:

    intervals = []

    for v in dd[key]:
      # print("\t",v)
      interval = INTERVAL(v['ty'],v['start'],v['stop'])
      intervals.append(interval)

    f= FIELD(intervals)

    # Eliminate anything which is unknown 
    if f.ty() != '?':
      fields.append(f)

  # Turn those fields into a sigma
  return SIGMA(fields)



"""```
Unknown Region Calculation Algorithm

Input:    list of intervals I
Output:   list of unknown regions to recurse on.

S ← sort intervals I    /* make a list from the set first */
p ← 0                   /* pointer to our unknown region start */
unknowns = []           /* here’s where we store the unknowns we find */
while stack not empty:  /* while we have an interval to look at */
  start,end ← pop(S)    /* get that interval */
  If p != start:        /* if there’s a gap… mark it as unknown */
    unknowns.append(unknown(p,start))
  p ← end               /* set the pointer to the end of the interval */
If b != msg_length:     /* if we finish the stack, mark remaining region */
  unknowns.append(unknown(end,msg_length))
return unknowns
```
"""

def msgs(data):
  header,data,trailer = parts(data)
  lines = data.split("\n")
  lines = [re.sub("[ |\t]+","",l,re.DOTALL) for l in lines]
  return lines


def hexmsgs(data):
  header,data,trailer = parts(data)
  lines = data.split("\n")
  lines = [re.sub("[ |\t]+","",l,re.DOTALL) for l in lines]
  lines = [bytes.fromhex(m) for m in lines] #Turn it into hex
  return lines

def intmsgs(data):
  header,data,trailer = parts(data)
  lines = data.split("\n")
  lines = [re.sub("[ |\t]+","",l,re.DOTALL) for l in lines]
  lines = [bytes.fromhex(m) for m in lines] #Turn it into hex
  lines = [[x for x in l] for l in lines]
  return lines

# We either leave stuff at the end
# or we exactly consume it all
def allornone(sigma,data):
  hexlines = hexmsgs(data)
  res = []
  for f in sigma.fields:
    leftovers = [len(hexlines[i]) -v.stop for i,v in enumerate(f.intervals)]
    all_zero = [x ==0 for x in leftovers]
    # print(f)
    # print("leftovers",leftovers)
    # print("all zero",all_zero)
    # print("any",not any(all_zero))

    # either
    #  we have leftovers
    #                   or we use it all
    if not any(all_zero) or all(all_zero):
      res.append(f)
    

  return SIGMA(res)

# Given a sigma and some msgs, identify unknown regions and create intervals
def unknownify(sigma,data):

  #print("original sigma interval lens",[len(f.intervals) for f in sigma.fields])

  lines = msgs(data)
  hexlines = hexmsgs(data)
  #print("lines",len(lines))


  # What does patch do?
  def patch(intervals,line):

    intervals = intervals[::-1]
    p = 0
    res =[]
    while intervals != []:
      interval = intervals.pop()
      start = interval.start
      end = interval.stop
      if p != start:
        res.append(INTERVAL("?",p,start))
      
      p = end
      res.append(interval)

    # Check if we've run out of intervals...
    # If we still have unexplained bytes... create a final unknown interval 
    maxlen = int(len(line)/2)
    if p != maxlen:
      #print("p",p,"end",end,"working on line",line,int(len(line)/2))
      res.append(INTERVAL("?",end,maxlen))
      
    return res

  def xpatch(intervals,line):
    return intervals

  newintervals = []
  patched_intervals = []
  for i in range(len(lines)):
    #print("working on line",i,len(lines[i]),lines[i])

    # If sigma is empty, make one big ? interval that's the entire length of the line
    if sigma.fields == []:

      #newintervals = [INTERVAL("?",0,len(lines[i]))]
      # Didn't have the right ending value
      newintervals = [INTERVAL("?",0,int(len(lines[i])/2))]
      
      patched_intervals.append(newintervals)
    else:


      intervals = [f.intervals[i] for f in sigma.fields]

      #print("\toriginal",intervals)
      newintervals = patch(intervals,lines[i])
      #print("\tpatched",newintervals)
      patched_intervals.append(newintervals)
      #newintervals.append( [f.intervals[i] for f in sigma.fields])

  #return patched_intervals
  rows = patched_intervals
  # print("rows")
  # for r in rows:
  #   print("\t",len(r))

  from collections import defaultdict
  dd = defaultdict(lambda:[])

  # for each row 
  for r in rows:
    # group the intervals together 
    for i,interval in enumerate(r):
      field_id = i
      
      dd[field_id].append(interval)


  # turn groups of intervals into fields
  fields = []
  for key in dd:
    
    # Need to carry annotation through
    f= FIELD(dd[key])
    #print("building field for key",key,len(dd[key]))
    if f.ty() == "?":
      if f.fixedwidth():
        f.annotation = "Unknown Type " + f.str_width() + " Byte(s)"
      else:
        f.annotation = "Unknown Type Variable Length " + f.str_width() + " Byte(s) Min"
    fields.append(f)
    # if f.ty() == "?" and all([i.start == i.stop for i in f.intervals]):
    #   pass
    # else:
    #   fields.append(f)

    # Eliminate anything which is unknown 
    # if f.ty() != '?':
    #   fields.append(f)

  # Turn those fields into a sigma
  fid = 0 
  # print("sigma.fields",sigma.fields)
  # for f in sigma.fields:
  #   print("sigma",f,len(f.intervals))
  # print("fields",fields)
  for i,f in enumerate(fields):
  #for i,f in enumerate(sigma.fields):
    #print("fid",fid)
    try:
      fidx = sigma.fields.index(f)
      fields[i].annotation = sigma.fields[fidx].annotation
      fields[i].intervals = sigma.fields[fidx].intervals
      # print("fidx",i,f,"found","anno",sigma.fields[fidx].annotation)
      # print("\t","lenintervals",len(f.intervals))
    except:
      # Could not find field or intervals

      # print("fidx",i,f,"missing")
      # print("\t","lenintervals",len(f.intervals))
      pass

    # if f.ty() != "?" :
    #   old_anno = sigma.fields[fid].annotation
    #   fields[i].annotation = old_anno
    #   fid+=1
  return SIGMA(fields)


def getunknownfields(sigma,data):
  s = unknownify(sigma,data)
  return [SIGMA([f]) for f in s.fields if f.ty()=="?"]



def applyfield(f,data):
  lines = msgs(data)

  # Make it hex
  lines = [bytes.fromhex(l) for l in lines]

  return f.apply(lines)

# given a sigma and some data (msgs) create a pretty printed version
def apply(sigma,data):

  # Fill in the unknown regions
  sigma = unknownify(sigma,data)
  #print(sigma)

  # Get the data we will need to cut up according to sigma
  lines = msgs(data)

  # We limit the lines displayed to 20
  if len(lines) > 20:
    lines = lines[:20]

  # Make it hex
  lines = [bytes.fromhex(l) for l in lines]

  f = sigma.fields[0]
  res = []
  for f in sigma.fields:
    res.append(f.apply(lines))
  # for r in res:
  #   print(r)
  def fieldscale(t):
    if t == "|":
      return 1
    else:
      return 2
  s = ""
  s += " ".join([f.ty()*fieldscale(f.ty())*len(res[i][0]) for i,f in enumerate(sigma.fields)])
  s+= "\n--\n"

  for i,m in enumerate(lines):

    vs =[v[i] for j,v in enumerate(res)]
    # If we made it a bar, we have do not try to make it hex
    def hexorbar(x):
      if x == '|':
        return x
      else:
        return (x).hex()

      #vs = [(v[i]).hex() for j,v in enumerate(res)]
    vs = [hexorbar(v) for v in vs]
    s+=" ".join(vs )+"\n"
  s+="--"
  for i,f in enumerate([f for f in sigma.fields if f.ty() != "|"]) :

    s+="\n"+str(i)+" "+f.ty() + " " 
    if f.annotation != None:
      s+=f.annotation + " " + str(f.value)
      if False: #Do you want to actually show the intervals inferred
        for i in f.intervals:
          s += "\n\t" + str(i)
      # if f.ty() == "I":
      #   print(f.apply(intmsgs(data)))
  return s
# ------------------------------------------------------------------------------------------------------------------------------------------------
# Abstract Data Structures 
# ------------------------------------------------------------------------------------------------------------------------------------------------

class INTERVAL:
  def __init__(self,ty,start,stop):
    self.ty = ty
    self.start = start
    self.stop = stop
    assert type(self.stop)==type(1)
    self.width = stop - start
    self.value = self.width
    if self.width ==0:
      self.value = 1

  def shift(self,v):
    self.start+=v
    self.stop+=v

  def __eq__(self,other):
    return self.ty == other.ty and self.start == other.start and self.stop == other.stop

  def intersect(self,other):
    return (self ^ other) or (self.start == other.start and self.stop == other.stop)

  def __xor__(self,other):

    # self.start <other.start < self.end
    # self.start <other.end < self.end

    contains_other_start = self.start < other.start and  other.start < self.stop
    contains_other_end =   self.start < other.stop  and  other.stop < self.stop

    contains_other = contains_other_start or contains_other_end

    contains_start = other.start < self.start and  self.start < other.stop 
    contains_end =   other.start < self.stop  and  self.stop < other.stop

    contains = contains_start or contains_end

    return contains_other or contains

  def __repr__(self):
    return "INTERVAL_"+str(self.ty)+"("+str((self.start,self.stop))+  ")"


  # we use this for conflcit handling
  def __ge__(self,other):
    # Use for conflict handling 
    return self.start >= other.stop

  def apply(self,msg):
    if self.start == self.stop:
      return "|" 
    else:
      return msg[self.start:self.stop]



# I = INTERVAL("int",0,10)
# C = INTERVAL("c",0,0)
# C1 = INTERVAL("c",1,1)
# D = INTERVAL("c",10,11)

# print(I ^ I, I == I)
# print(I ^ C, I == C)
# print(C ^ C, C == C)
# print(I ^ C1, I == C1)
# print(I ^ D, I == D)

import uuid

class FIELD:          # FIELD : [INTERVAL]
  def __init__(self,xs,annotation=None,valuescale=1.0):
    self.intervals = xs
    self.annotation = annotation
    self.width = sum([i.value for i in self.intervals])
    self.valuescale = valuescale
    self.value = (self.width * self.valuescale)  # *.999 # This would allow us to prefer wider fields all things being equal
    self.id = str(uuid.uuid4())

  def ty(self):
    return self.intervals[0].ty
    
  # For all intervals, if they all are equal then the fields are equal
  def __eq__(self,other):
    return all([self.intervals[i] == other.intervals[i] for i in range(len(self.intervals))])

  def __lt__(self,other):
    return all([self.intervals[i].stop < other.intervals[i].start for i in range(len(self.intervals))])

  # for all intervals if any intersect then the fields intersect
  def __xor__(self,other):
    return any([self.intervals[i] ^ other.intervals[i] for i in range(len(self.intervals))])

  # Use for conflicts
  def __ge__(self,other):
    return all([self.intervals[i] >= other.intervals[i] for i in range(len(self.intervals))])

  def intersect(self,other):
    return (self ^ other) or (any([self.intervals[i].intersect( other.intervals[i]) for i in range(len(self.intervals))]))   

  def __str__(self):
    x = self.intervals[0]
    startflag = ""
    stopflag = ""

    if not self.startallsame():
      startflag="*"
    if not self.stopallsame():
      stopflag="*"


    return "FIELD_" +str((x.ty+"("+str(x.start)+startflag+","+str(x.stop)+stopflag+ ")"))
  

  def str_width(self):
    x = self.intervals[0]
    startflag = ""
    stopflag = ""

    if not self.startallsame():
      startflag="*"
    if not self.stopallsame():
      stopflag="*"

    if self.fixedwidth():
      return str(x.stop - x.start)
    else: 
      return str(min([i.stop - i.start for i in self.intervals]))

    #return "FIELD_" +str((x.ty+"("+str(x.start)+startflag+","+str(x.stop)+stopflag+ ")"))
  
  def __repr__(self):
    return str(self)

  def startallsame(self):
    return 1==len(set([i.start for i in self.intervals]))

  def stopallsame(self):
    return 1==len(set([i.stop for i in self.intervals]))

  def fixedwidth(self):
    return 1 == len(set([i.stop - i.start for i in self.intervals]))



  def apply(self,msgs):
    res = []
    for i in range(len(msgs)):
      v = msgs[i]
      f = self.intervals[i]
      r = f.apply(v)
      #print(r)
      res.append(r)
    return res
    #return [self.intervals[i].apply(v) for i,v in enumerate(msgs)]


# A1 = INTERVAL("A",0,4)
# A2 = INTERVAL("A",0,6)

# B1 = INTERVAL("B",4,8)
# B2 = INTERVAL("B",10,12)

# C1 = INTERVAL("C",4,4)
# C2 = INTERVAL("C",4,4)

# FA = FIELD([A1,A2])
# FB = FIELD([B1,B2])
# FC = FIELD([C1,C2])

# print(FA==FB,FA ^ FB)
# print(FA==FC,FA ^ FC)
# print(FC==FC,FC ^ FC)

class SIGMA:    # SIGMA : [FIELD]
  def __init__(self,fields):
    def fieldsort(f):
      return (f.intervals[0].start,f.intervals[0].stop)
      
    self.fields = sorted(fields,key=fieldsort)

    # Added a unique sigma_ID for unification
    self.id = str(uuid.uuid4())
    self.value = sum([f.value for f in self.fields])


    # Check that fields are not redundant: Are a set
    # and that fields do not intersect: Are well formed
    for i in range(len(self.fields)):
      for j in range(i+1,len(self.fields)):
        
        F1 = self.fields[i]
        F2 = self.fields[j]
        #print(i,j,F1==F2,F1 ^ F2)

        # No Duplicate Fields
        assert((F1==F2)==False)

        # No internal Intersections within the Sigma
        
        assert((F1 ^ F2)==False)

  def __and__(self,other):
    res = []
    for my_field in self.fields:
      for other_field in other.fields:
        #assert((my_field == other_field) or not(my_field ^ other_field))
        res.append((my_field == other_field) or not(my_field ^ other_field))
    return all(res)


  def __repr__(self):
    return "SIGMA("+str(self.fields)+")"

  def __eq__(self,other):
    if len(self.fields) == len(other.fields):
      return all([self.fields[i] == other.fields[i] for i in range(len(self.fields))])
    else:
      return False


  # def __xor__(self,other):
  #   res = []
  #   for my_field in self.fields:
  #     for other_field in other.fields:
  #       #assert((my_field == other_field) or not(my_field ^ other_field))
  #       res.append(not(my_field ^ other_field))
    return all(res)

    # Use for conflicts
  def __ge__(self,other):
    

    # Assumes fields in SIGMA.fields are sorted.
    self_first=self.fields[0]
    other_last = other.fields[-1]
    if False:
      print("You compared",self,">=",other)
      print("Which becomes",self_first,">=",other_last)
      print(self_first>=other_last)
    return self_first>=other_last
    #return all([self.intervals[i] >= other.intervals[i] for i in range(len(self.intervals))])

  def apply(self,txt):
    return apply(self,txt).upper()


  def unknowns(self,txt):
    sunk = unknownify(self,txt)

# S1 = SIGMA([FA,FB])
# S2 = SIGMA([FC])

# # S1 & S2 : Bool // Can these be unified
# print(S1 & S2)


def UNIFY(S1,S2):
  assert(S1 & S2)
  res = S1.fields
  for F in S2.fields:
    # Check if our field is equal to any in S1... 
    if not any([F == G for G in S1.fields]):
      # Doesn't equal,. we can add
      # If we have a field in S2 which isn't already in S1, then we can add it. 
      res.append(F)

  # If there are intersections, the well formedness property of the SIGMA constructor will barf. 
  return SIGMA(res)

# def UNIFY(S1,S2):
#   return deconflict([S1,S2])


#from deconflict import deconflict
from maxdistsearch import deconflict

def mapUNIFY(xs):
  s = SIGMA([])
  while xs != []:
    h = xs.pop()
    try:
      s = UNIFY(s,h)
    except:
      #print("Error Unifying",s,"and",h)
      s = deconflict([s,h])
  return s

def mapUNIFY(xs):
  if len(xs) == 1:
    return xs[0]
  else:
    return deconflict(xs)
  s = SIGMA([])
  while xs != []:
    h = xs.pop()
    try:
      s = UNIFY(s,h)
    except:
      #print("Error Unifying",s,"and",h)
      s = deconflict([s,h])
  return s

# S1 = SIGMA([FIELD([INTERVAL("A",0,4)]), FIELD([INTERVAL("C",4,4)]) ] )
# S2 = SIGMA([FIELD([INTERVAL("A",0,4)]),FIELD([INTERVAL("A",4,8)])  ] )
# print(S1 & S2)
# S3 = UNIFY(S1,S2)
# print(S1)
# print(S2)
# print(S3)

# String --> Sigma
# String --> Field Chunks
# Line --> [Interval]
# [Interval] --> FieldDefs --> [Interval]
# [Interval] --> [Fields] --> [Fields]

# String to parts

# Spec





# def intervalizeline(xs,header):
#   xs = re.sub('[ \t]+',' ',xs,flags=re.M)
#   # print("got",xs)
#   # print(xs)
#   #print("joined",joinline(xs))
#   xs = xs.split(" ")
#   res = []
#   start = 0
#   end = 0
#   field_id = 0
#   for x in xs:
#     ty = header[field_id]
#     if x == "|":
#       end = start
      
#       v = {'ty':ty,'field_id':field_id,'start':start,'stop':end,'val':x}
#       #res.append(("c",field_id,start,end,x))
#       res.append(v)
#     else:
#       end = start + len(x)
#       v = {'ty':ty,'field_id':field_id,'start':start,'stop':end,'val':x}
#       #res.append(("x",field_id,start,end,x))
#       res.append(v)
#     start = end
#     field_id+=1
#   return res

# def intervalizerows(xs,header):
#   xs =xs.strip().split("\n")
#   res = []
#   for x in xs:
#      res.append(intervalizeline(x,header))
#   return res


# def parseheader(header):
#   header = re.sub('[ \t]+',' ',header.strip(),flags=re.DOTALL)
#   header_fields = header.split(" ")
#   #just use the first chracter as a key
#   header_fields = [x[0] for x in header_fields]
#   return header_fields
# #intervalizerows(xs)

# def parsetrailer(trailer):
#   trailer = trailer.strip()
#   field_types = [x.strip() for x in trailer.split("\n")]
#   for x in field_types:
#     pass


# def ascii2sigma(data):
 
#   # break ASCII into parts
#   header,data,trailer = parts(data)
#   header = parseheader(header)
#   # turn the data into rows of intervals
#   rows = intervalizerows(data,header)

#   from collections import defaultdict
#   dd = defaultdict(lambda:[])

#   # for each row 
#   for r in rows:
#     # group the intervals together 
#     for interval in r:
#       field_id = interval['field_id']
#       dd[field_id].append(interval)


#   # turn groups of intervals into fields
#   fields = []
#   for key in dd:
#     intervals = []

#     for v in dd[key]:
#       # print("\t",v)
#       interval = INTERVAL(v['ty'],v['start'],v['stop'])
#       intervals.append(interval)

#     f= FIELD(intervals)

#     # Eliminate anything which is unknown 
#     if f.ty() != '?':
#       fields.append(f)

#   # Turn those fields into a sigma
#   return SIGMA(fields)



    
  # # front
  # if not all(interval.start == 0 for interval in sigma.fields[0].intervals):
  #   # We need to add front intervals




  # # back
  # backs = []
  # for i,interval in enumerate(sigma.fields[-1].intervals):
  #   #print( all(interval.stop == 0 for interval in sigma.fields[0].intervals))
  #   backs.append(interval.stop == len(lines[i]))
  # if not all(backs):
  #   # We need to add back intervals

# u = unknownify(s,data)

# Parsing Phase

# ASCII --> FIELDS 
# ASCII --> Types
# ASCII --> msgs

# given a sigma and some data (msgs) create a pretty printed version
# def apply(sigma,data):
#   sigma = unknownify(sigma,data)
#   lines = msgs(data)
#   f = sigma.fields[0]
#   res = []
#   for f in sigma.fields:
#     res.append(f.apply(lines))
#   # for r in res:
#   #   print(r)
#   print(" ".join([f.ty()*len(res[i][0]) for i,f in enumerate(sigma.fields)]))
#   print("--")
#   for i,m in enumerate(lines):
#    print(" ".join([v[i] for j,v in enumerate(res)]))
#   print("--")




# d1 = """

# A  B  ? | ?
# --
# aa bb xxdd | yyzz
# aa bb xxdd | yyzz
# --
# """

# d2 = """

# ?  B  ? D   ? Z
# --
# aa bb xx dd yy zz
# aa bb xx dd yy zz
# --
# """

# s1 = ascii2sigma(d1)

# s2 = ascii2sigma(d2)


# print("ASCII Input d1")
# print(d1.strip())
# print("")
# print("ASCII Input d2")
# print(d2.strip())
# print("")
# print("sigma s1 created from d1: ",s1)
# print("")
# print("Pretty Print of s1")
# print("")
# apply(s1,d1)
# print("")
# print("sigma s2 created from d2: ",s2)
# print("")
# print("Pretty Print of s2")
# print("")
# apply(s2,d2)

# print("")
# s3 = UNIFY(s1,s2)
# print("s3 created from UNIFY(s1,s2): ",s3)
# print("")
# print("Pretty Print of s3")
# print("")
# apply(s3,d2)


# print("Original: S")
# print(re.sub("[ \t]+"," ",data,flags=re.MULTILINE))
# print("")

# print("S2")
# print("")
# apply(s2,data) 
# print("")
# # print("After Unification")
# # print("")
# # apply(u,data)

# u = UNIFY(s,s2)
# print("")
# print("After Unification and Unknownification")
# print("")
# apply(u,data)

# Pretty Printing Phase

# FILEDS --> msgs --> Pretty Print
# Fields --> Unknowns # Add those unknowns in 
# Fields --> LookupData

# d1 = """

# ?? | ???? IIII ??
# --
# aa | bbbb 1234 XX
# aa | bbb  6789 XX
# --
# """

# s1 = ascii2sigma(d1)

# print(d1)
# print(s1)

# d2 = """

# LL  TTTT ???? | ??
# --
# aa bbbb 1234 | XX
# aa bbb  6789 | XX
# --
# """

# s2 = ascii2sigma(d2)

# print(d2)
# print(s2)


# s3 = UNIFY(s1,s2)

# print("")
# print(s3)
# print("")
# apply(s3,d1)

if False:

  def lenfinder(ascii):
    lines = msgs(ascii)
    # do some conversion from hex to int list

    
  d3 = """
  A ?
  --
  80 6FA30102B00818
  80 6FA30112800878
  10 03A30001004006729E99940012120B
  10 03A30001003007709C98940012121F
  10 03A30001003806739C9B9400121202
  80 6FA30200800041
  --
  """

  ascii2sigma(d3)



  """ascii2sigma using hex"""

  # String --> Sigma
  # String --> Field Chunks
  # Line --> [Interval]
  # [Interval] --> FieldDefs --> [Interval]
  # [Interval] --> [Fields] --> [Fields]

  # String to parts

  # Spec






  d3 = """
  A ? C ?
  --
  80 6FA3 0102 B00818
  80 6FA3 0112 800878
  10 03A3 0001 004006729E99940012120B
  10 03A3 0001 003007709C98940012121F
  10 03A3 0001 003806739C9B9400121202
  80 6FA3 0200 800041
  --
  """

  print(d3)

  s3 = ascii2sigma(d3)
  print(s3)

  print(apply(s3,d3))

  d4 = """
  A ?? CC ???
  --
  80 6fa3 0102 b00818
  80 6fa3 0112 800878
  10 03a3 0001 004006729e99940012120b
  10 03a3 0001 003007709c98940012121f
  10 03a3 0001 003806739c9b9400121202
  80 6fa3 0200 800041
  --
  """

  s4 = ascii2sigma(d4)

  print(s4)





  d5 = """
  ? X
  --
  806FA30102B0 0818
  806FA3011280 0878
  1003A30001004006729E99940012 120B
  1003A30001003007709C98940012 121F
  1003A30001003806739C9B940012 1202
  806FA3020080 0041
  --
  """

  s5 = ascii2sigma(d5)

  print(s5)


  s6 = UNIFY(s4,s5)
  print(s6)

  print(apply(s6,d5))

  print("")

  print(s6.apply(d5))




  def mklv():
    import random
    def v():
      return random.randrange(0,256)
    l = random.randrange(1,20)
    xs = [v() for i in range(l)]
    return bytes([l]),bytes(xs)

  def mkds():
    s = "L ?"
    s+="\n--\n"
    for i in range(8):
      l,xs = mklv()
      s+=l.hex() + " " +xs.hex()+"\n"
    s+="--"
    return s


  s = mkds()
  print(s)

  s1 = ascii2sigma(s)

  print(s1)


  print("\n".join(msgs(s)))

if __name__=="__main__":
  # s = SIGMA([])
  # txt = """
  # ?
  # --
  # 806FA30102B00818
  # 806FA30112800878
  # 1003A30001004006729E99940012120B
  # 1003A30001003007709C98940012121F
  # 1003A30001003806739C9B9400121202
  # 806FA30200800041
  # --
  # """

  # print(s.apply(txt))
  #print(unknownify(s,txt))
  f1a = FIELD([INTERVAL("x",0,3),INTERVAL("x",0,4)])
  f1b = FIELD([INTERVAL("|",5,5),INTERVAL("|",5,5)])
  s1 = SIGMA([f1a,f1b])
  print(s1)
