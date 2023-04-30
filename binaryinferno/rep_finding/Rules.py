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



# Here's where we define our atomic serialization patterns for the pattern search

#
# Does everything start with a 0? 
#
def leadingZerosCheck(zs,w=1,t=0):
    
    for xs in zs:
        if len(xs)<w:
            return False
        try:
            # we do this to handle multple byte fields

            for x in xs[:w]:
                if x !=0:
                    return False
        except:
            return False
    else:
        return True


# 
# Does eeverything start with a 1?  
#
def leadingOnesCheck(zs):
    
    for xs in zs:
        try:
            if xs[0]!=1:
                return False
        except:
            return False
    else:
        return True


def xvl(zs):
    new_zs = []
    if len(zs)>1:
        if leadingZerosCheck(zs):
            return None
        if leadingOnesCheck(zs):
            return None
    for xs in zs:
        if len(xs)<=1:
            return None
        h,*t = xs
        if h > len(t):
            return None
        new_zs.append(t[h:])
    return new_zs

# Old VL 
def vl(zs):
    new_zs = []

    if [] in zs:
        return None
    
    for xs in zs:
        try:
            h,*t = xs
            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs

# Double LLV
def llv(zs):    #int.from_bytes(bytes([0,0,0,1]),"little")
    new_zs = []
    if [] in new_zs:
        return None

    for xs in zs:
        try:
            h1,h2,*t = xs
            h = (h1<<8)+h2
            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs


def proto_lv(zs,l_width,endian):
    #int.from_bytes(bytes([0,0,0,1]),"little")
    new_zs = []

    if [] in new_zs:
        return None
    if len(zs)>1:
        if leadingZerosCheck(zs,l_width):
            return None
    for xs in zs:
        try:
            # break up
            # number of h's = l_width
            if l_width == 1:
                h1,*t = xs
                hs = [h1]
            elif l_width == 2:
                h1,h2,*t = xs
                hs = [h1,h2]
            elif l_width == 3:
                h1,h2,h3,*t = xs
                hs = [h1,h2,h3]
            elif l_width == 4:
                h1,h2,h3,h4,*t = xs
                hs = [h1,h2,h3,h4]
            else:
                1/0
            #h1,h2,*t = xs
            
            # assemble h
            #int.from_bytes(bytes([0,0,0,1]),"little")
            #h = (h1<<8)+h2
            h = int.from_bytes(bytes(hs),endian)


            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs







def proto_tlv(zs,l_width,endian):
    #int.from_bytes(bytes([0,0,0,1]),"little")
    new_zs = []

    if [] in new_zs:
        return None
    # need to bring this back

    # if len(zs)>1:
    #     if leadingZerosCheck(zs,l_width):
    #         return None
    for xs in zs:
        try:
            # break up
            # number of h's = l_width
            if l_width == 1:
                h1,*t = xs
                hs = [h1]
            elif l_width == 2:
                h1,h2,*t = xs
                hs = [h1,h2]
            elif l_width == 3:
                h1,h2,h3,*t = xs
                hs = [h1,h2,h3]
            elif l_width == 4:
                h1,h2,h3,h4,*t = xs
                hs = [h1,h2,h3,h4]
            else:
                1/0
            #h1,h2,*t = xs
            
            # assemble h
            #int.from_bytes(bytes([0,0,0,1]),"little")
            #h = (h1<<8)+h2
            h = int.from_bytes(bytes(hs),endian)


            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs

def vqvl(zs):
    new_zs = []
    if len(zs)>1:
        if leadingZerosCheck(zs):
            return None
    for xs in zs:
        try:
            if len(xs)<1:
                return None
            q,*t = xs

            # reenabled
            # if q ==0 and len(t) > 0:
            #     return None

            for i in range(q):
                l,*t = t
                if l>len(t):
                    return None
                t=t[l:]
            new_zs.append(t)
        except:
            return None
    return new_zs




def vqtlv(zs):
    new_zs = []
    if len(zs)>1:
        if leadingZerosCheck(zs):
            return None
    for xs in zs:
        try:
        
            if len(xs)<1:
                #print("len too short")
                return None
            q,*t = xs
            # if q ==0 and len(t) > 0:
            #     return None
            for i in range(q):
                tag,l,*t = t
                if l>len(t):
                    #print("len(t) too short")
                    return None
                t=t[l:]
            new_zs.append(t)
        except:
            #for xs in zs:
            #    print("xs",xs)
            
            return None
    return new_zs

# Old VL 
def tlv(zs):
    new_zs = []

    if [] in zs:
        return None
    
    for xs in zs:
        try:
            tag,h,*t = xs
            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs


def vqfw_proto(zs,w,q_w):
    new_zs = []
    if len(zs)>1:
        if leadingZerosCheck(zs):
            return None
    for xs in zs:
        if len(xs)<w+1:
            # Tricky case... zero quantities
            #if len(xs) == 1 and xs[0] == 0:
            if len(xs) > 0 and xs[0] == 0:
                pass
            else:
                return None
        h,*t = xs
        if h*w> len(t) :
            return None
        new_zs.append( t[h*w:])
    return new_zs

# This is the vresion we are hacking on 

def qqfw_proto(zs,w,l_width,endian='big'):
    new_zs = []
    if len(zs)>1:
        if leadingZerosCheck(zs,l_width):
            return None
    for xs in zs:

        # This is probs garbage.
        # Need at least as many bytes as necessary to take 1 Q field
        if len(xs)<l_width:
            return None
            # Tricky case... zero quantities
            #if len(xs) == 1 and xs[0] == 0:
            # if len(xs) > 0 and xs[0] == 0:
            #     pass
            # else:
            #     return None
        try:
            # break up
            # number of h's = l_width
            if l_width == 1:
                h1,*t = xs
                hs = [h1]
            elif l_width == 2:
                h1,h2,*t = xs
                hs = [h1,h2]
            elif l_width == 3:
                h1,h2,h3,*t = xs
                hs = [h1,h2,h3]
            elif l_width == 4:
                h1,h2,h3,h4,*t = xs
                hs = [h1,h2,h3,h4]
            else:
                1/0
            #h1,h2,*t = xs
            
            # assemble h
            #int.from_bytes(bytes([0,0,0,1]),"little")
            #h = (h1<<8)+h2
            h = int.from_bytes(bytes(hs),endian)
            #h,*t = xs
            #print("applying","q"*l_width,"v"*w,"hs",hs,"h",h,"t",t,"xs",xs)
            if h*w> len(t) :
                return None
            new_zs.append( t[h*w:])
        except:
            return None
    return new_zs



def vqfw(w):
    return lambda zs: vqfw_proto(zs,w,1)


def qqfw(w,qw,endian):
    return lambda zs: qqfw_proto(zs,w,qw,endian)

# assert(vqfw(1)([[1,2]]) ==[[2]])
# assert(vqfw(1)([[0,0]]) ==[[0]])
# assert(vqfw(1)([[1,0,2]]) ==[[2]])
# assert(vqfw(5)([[0,0,2]]) ==[[0,2]])


# This needs to be debugged
def vqfwps_proto(zs,p,s,w):
    new_zs = []
    for xs in zs:
        #if len(xs)<1+p+s+w:
        if len(xs)<1+p+s:
            # Tricky case... zero quantities
            if len(xs) == 1+p+s and xs[p] == 0:
                1+1
            else:
                return None
        xs = xs[p:]
        h,*t = xs
        t = t[s:]
        if h*w> len(t) :
            return None
        new_zs.append( t[h*w:])
    return new_zs

    # [q] s(w)^q
    # [0] s
    # [1] s w
    # [2] s w w 

def vqfwps(p,s,w):
    return lambda zs: vqfwps_proto(zs,p,s,w)


def take1 (zs):
    new_zs = []
    for xs in zs:
        if len(xs) == 0:
            return None
        new_zs.append(xs[1:])
    return new_zs




MINFWW =2
MAXFWW = 33

rules = []
from collections import defaultdict
rules_lzf = defaultdict(lambda:None)



if False:
    rules.append(("VQVL",vqvl)) # Q (LV)^Q
    rules.append(("QTLV",vqtlv)) # Q (TLV)^Q
    rules.append(("TLV",tlv))     # L (V)^L
    # rules.append(("TTLLV",tlv))     # L (V)^L
    rules.append(("LV",vl))     # L (V)^L
    #rules.append(("LLV",llv))   # LL (V)^LL


    # rules.append(("LLVBE",lambda xs: proto_lv(xs,2,'big')))
    # rules.append(("LLLVBE",lambda xs: proto_lv(xs,3,'big')))
    # rules.append(("BE_LLLLV",lambda xs: proto_lv(xs,4,'big')))

def mk_lv(w,endian):
    return lambda zs: proto_lv(zs,w,endian)




def mk_qfw(w,q_w,endian):
    return lambda zs: qqfw_proto(zs,w,q_w,endian)

# Covers class of :
# LL V^ LL to LLLL V ^ LLLL big and little endian


# [xs] --> x
def get_l(xs,l_width,endian):
    res = []
    for x in xs:
        if len(x)<l_width:
            return None
        else:
            res.append(x[:l_width])
    return res

def allzero(vs):
    pass

def allsame(vs):
    return len(set(vs)) ==1

STRICT = False

def q_pat(zs,q_width,endian,pat):
    new_zs = []
    # if len(zs)>1:
    #     if leadingZerosCheck(zs):
    #         return None
    for xs in zs:
        try:
            if len(xs)<q_width:
                return None
            

            if q_width == 1:
                h1,*t = xs
                hs = [h1]
            elif q_width == 2:
                h1,h2,*t = xs
                hs = [h1,h2]
            elif q_width == 3:
                h1,h2,h3,*t = xs
                hs = [h1,h2,h3]
            elif q_width == 4:
                h1,h2,h3,h4,*t = xs
                hs = [h1,h2,h3,h4]
            else:
                1/0
            #h1,h2,*t = xs
            
            # assemble h
            #int.from_bytes(bytes([0,0,0,1]),"little")
            #h = (h1<<8)+h2
            q = int.from_bytes(bytes(hs),endian)

            # # be strict
            if STRICT:
                if q == 0:
                    return None

            #q,*t = xs

            # reenabled
            # if q ==0 and len(t) > 0:
            #     return None

            if True:
                for i in range(q):
                    #print("\t",i,"applying",pat,"to",t)
                    # If t == [], I can't apply a pattern to it
                    if t == []:
                        return None
                    t = pat([t])
                    #print("\t\tgot",t)
                    # If I failed to apply the pattern then halt
                    if t == None:
                        return None
                    else:
                        t = t[0]
            new_zs.append(t)
        except:
            return None
    return new_zs


# This handles t,l,endian

def tlv_pat(zs,t_width,l_width,endian):

    #print("\ttlv_pat","t",t_width,"l",l_width,"zs",zs)
    #int.from_bytes(bytes([0,0,0,1]),"little")
    new_zs = []

    if [] in zs:
        return None
    # if len(zs)>1:
    #     if leadingZerosCheck(zs,l_width):
    #         return None
    for xs in zs:
        
        xs = xs[t_width:]

        try:
            # break up
            # number of h's = l_width
            if l_width == 1:
                h1,*t = xs
                hs = [h1]
            elif l_width == 2:
                h1,h2,*t = xs
                hs = [h1,h2]
            elif l_width == 3:
                h1,h2,h3,*t = xs
                hs = [h1,h2,h3]
            elif l_width == 4:
                h1,h2,h3,h4,*t = xs
                hs = [h1,h2,h3,h4]
            else:
                1/0
            #h1,h2,*t = xs
            
            # assemble h
            #int.from_bytes(bytes([0,0,0,1]),"little")
            #h = (h1<<8)+h2
            h = int.from_bytes(bytes(hs),endian)

            # # Be strict
            if STRICT:
                if h == 0:
                    return None

            if h > len(t):
                return None
            new_zs.append(t[h:])
        except:
            return None
    return new_zs


if False:
    for endian in ['big','little']:
        for i in [2,3,4]:
            label = str(i)+ "LV"+"_"+endian
            rules.append((label,mk_lv(i,endian))) 

            # for each pattern, make a zero_function

            # label = str(i)+"Q" + "FW2V_"+endian
            # rules.append((label,qqfw(2,i,endian)))


    for endian in ['big']:
        for q in [2]:

            for v in [3]:

                label = str(q)+"Q" + "FW"+str(v)+"V_"+endian
                rules.append((label,mk_qfw(v,q,endian)))

    for i in range(MINFWW,MAXFWW):
        rules.append(("VQFW_"+str(i),vqfw(i)))


if False:
    rules.append(("lv*",lambda xs:None))
    rules.append(("tlv*",lambda xs:None))


# For each LV, I need a corresponding, select L function,  non-leading-zero function and not all same function

# This function will get our length 
def get_length(t_width,l_width):
    return lambda xs: [x[t_width:t_width+l_width] for x in xs]

def get_quantity(q_width):
    return lambda xs: [x[:q_width] for x in xs]
    

def mk_tlv_pat(t_width,l_width,endian):
    return lambda zs: tlv_pat(zs,t_width,l_width,endian)

# Given a pat, make a Q(PAT)^Q
def mk_q_pat(q_width,endian,pat):
    return lambda zs: q_pat(zs,q_width,endian,pat)

# Function to get the length part of a pattern 
def mk_lzf_pat(q_width,t_width,l_width):
    return lambda xs: xs[q_width+t_width:q_width+t_width+l_width]

#function to get the q part of a pattern
def mk_lzf_q(q_width):
    return lambda xs: xs[:q_width]


for endian in ['big','little']:
    for q_width in [1,2]:

        for v in [2,3,4,5,6,7,8]:

            label = str(q_width)+"Q" + "FW"+str(v)+"V_"+endian
            rules.append((label,mk_qfw(v,q_width,endian)))
            rules_lzf[label] = mk_lzf_q(q_width)

    # Q --> Non-constant
    # L --> Non-constant

# P : LV (naz,nas)
# P : TLV (naz,nas)
# Q( P )  (naz)
# 

def mk_label(q_width,t_width,l_width,endian):
    return "".join(["Q"*q_width,"T"*t_width,"L"*l_width,"V","_"+endian])

if True:
    for endian in ['big','little']: 
        for t_width in [0,1,2]:
            for l_width in [1,2,3]: #,2]:
                q_width=0
                label = str(t_width)+"T_"+str(l_width)+ "L_V"+"_"+endian
                #label=mk_label(q_width,t_width,l_width,endian)
                f = mk_tlv_pat(t_width=t_width,l_width=l_width,endian=endian)
                #rules.append((label,mk_lv(i,endian))) 
                rules.append((label,f))
                rules_lzf[label] = mk_lzf_pat(q_width,t_width,l_width)

                q_width = l_width
                qf = mk_q_pat(q_width=q_width,endian=endian,pat=f)
                label = str(q_width)+"Q_"+str(t_width)+"T_"+str(l_width)+ "L_V"+"_"+endian
                #label=mk_label(q_width,t_width,l_width,endian)
                rules.append((label,qf))                    
                # lzf = ("L",0,i,endian)
                rules_lzf[label] = mk_lzf_q(q_width)

        # for i in [1,2,3,4]:
        #     label = str(i) + "T"  + "_"+ str(i)+ "L_V"+"_"+endian
        #     rules.append((label,mk_lv(i,endian))) 

        #     lzf = ("TL",i,i+i,endian)
        #     rules_lzf[label] = lzf
rules.append(("0T_1L_V_big*",lambda xs: None))
rules.append(("1T_1L_V_big*",lambda xs: None))
rules.append(("2T_2L_V_big*",lambda xs: None))
rules.append(("0T_1L_V_little*",lambda xs: None))
rules.append(("1T_1L_V_little*",lambda xs: None))
rules.append(("2T_2L_V_little*",lambda xs: None))
rules.append(("BYTE",take1))


rules_names = [r[0] for r in rules]
rules_funcs = [r[1] for r in rules]
if False:
    rules_star_pairs =[(rules_names.index("TLV"),rules_names.index("tlv*")),(rules_names.index("LV"),rules_names.index("lv*"))] #,
rules_star_pairs = []
rules_star_pairs = [
(rules_names.index("0T_1L_V_big"),rules_names.index("0T_1L_V_big*")),
(rules_names.index("1T_1L_V_big"),rules_names.index("1T_1L_V_big*")),
(rules_names.index("2T_2L_V_big"),rules_names.index("2T_2L_V_big*")),
(rules_names.index("0T_1L_V_little"),rules_names.index("0T_1L_V_little*")),
(rules_names.index("1T_1L_V_little"),rules_names.index("1T_1L_V_little*")),
(rules_names.index("2T_2L_V_little"),rules_names.index("2T_2L_V_little*"))]

#rules_star_pairs = []
rules_star_ids = [x[1] for x in rules_star_pairs]

def filterrules(label,rules_names,rules_funcs,rules_star_pairs):
    rules_label = []    
    rules_names_label = []
    rules_funcs_label = []
    rules_star_pairs_label = []
    #print("Rule filtering enumerations")
    for i,v in enumerate(rules_names):
        #print("\t","i",i,"v",v,"label",label," not in",v,":",label not in v)

        if label not in v:
            rules_label.append((rules_names[i],rules_funcs[i]))
            rules_names_label.append(rules_names[i])
            rules_funcs_label.append(rules_funcs[i])
    rules_star_pairs_label = [r for r in rules_star_pairs if label not in rules_names[r[0]]]
    rules_star_ids_label = [x[1] for x in rules_star_pairs_label]
    return rules_label,rules_names_label,rules_funcs_label,rules_star_pairs_label,rules_star_ids_label


rules_be,rules_names_be,rules_funcs_be,rules_star_pairs_be,rules_star_ids_be = filterrules("little",rules_names,rules_funcs,rules_star_pairs)
rules_le,rules_names_le,rules_funcs_le,rules_star_pairs_le,rules_star_ids_le = filterrules("big",rules_names,rules_funcs,rules_star_pairs)
rules_xe,rules_names_xe,rules_funcs_xe,rules_star_pairs_xe,rules_star_ids_xe = filterrules("qzx",rules_names,rules_funcs,rules_star_pairs)


def getrules(key):
    if key == "little":
        #rules_le,rules_names_le,rules_funcs_le,rules_star_pairs_le,rules_star_ids_le = filterrules("big",rules_names,rules_funcs,rules_star_pairs)
        return (rules_le,rules_names_le,rules_funcs_le,rules_star_pairs_le,rules_star_ids_le,rules_lzf)
    elif key == "big":
        #rules_be,rules_names_be,rules_funcs_be,rules_star_pairs_be,rules_star_ids_be = filterrules("little",rules_names,rules_funcs,rules_star_pairs)
        return (rules_be,rules_names_be,rules_funcs_be,rules_star_pairs_be,rules_star_ids_be,rules_lzf)
    else:
        return (rules_xe,rules_names_xe,rules_funcs_xe,rules_star_pairs_xe,rules_star_ids_xe,rules_lzf )

#rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids = filterrules("little",rules_names,rules_funcs,rules_star_pairs)


if __name__ == "__main__":
    for i,v in enumerate(rules_names):
        f = rules_funcs[i]
        print(v,rules_lzf[v])
        lzf = rules_lzf[v]
        # for ds in [[1,2,88,99,77],[2,2,88,99,1,77],[0,1,0,2,88,99,77],[1]]:
        #     print("\t",[ds],"-->",lzf(ds))
            #print("\t",[ds],"-->",f([ds]))
        # print("\t",[[1,2,88,99,77]],"-->",f([[1,2,88,99,77]]))
        # print("")
        # print("\t",[[2,2,88,99,1,77]],"-->",f([[2,2,88,99,1,77]]))
        # print("")
        # print("\t",[[0,1,0,2,88,99,77]],"-->",f([[0,1,0,2,88,99,77]]))
        # print("")
        # print("\t",[[1]],"-->",f([[1]]))
        # print("")


    for key in "big","little","any":
        print("")
        print("key",key)
        rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids,rules_lzf = getrules(key)
        for r in rules_names:
            print("\t",r)

    for rules in [rules_be,rules_le,rules_xe]:
        print("")
        for r in rules:

            print("\t",r,rules_lzf[r[0]])
