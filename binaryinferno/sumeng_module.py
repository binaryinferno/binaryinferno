# This file is part of BinaryInferno, a tool for binary protocol reverse engineering.
# Copyright (C) 2023 Jared Chandler (jared.chandler@tufts.edu)
# Adapted from Lauren Labell's work on checksum finding

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

import re
import functools
import operator
import sys
from collections import defaultdict



def sumeng(msgs=None,goal=None,csumwidth=8):
    #print("searching for width",csumwidth)
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

    # returns True if an algorithm is a duplicate
    def duplicate(foldOp, finalOp, magicVal):
        if (finalOp == operator.add or finalOp == operator.xor) and magicVal == 0:
            return True
        if foldOp == operator.add and finalOp == twosComp:
            return True
        if foldOp == operator.sub and finalOp == twosComp:
            return True
        if finalOp == operator.xor and magicVal == ((1 << width) - 1):
            return True

        return False

    def readexample(file_name):
        f = open(file_name)
        data = f.read()
        f.close()
        return data

    def cleanHex(data):
        data = data.strip()
        data = re.sub(' ','',data)
        data = re.sub('0x','',data)
        data = re.sub(',','',data)
        return data

    # Let 0 represent the end of the list
    def slice(msg, start, end):
        return msg[start:] if end == 0 else msg[start:end]

    # Check that we have more than one value in our candidate checksum bytes. 
    def checkpatch(i):
        return len(set([ msg[i] for msg in msgs ])) > 1

    def in_payload(check_index, start, stop, length):
        pos_index = check_index % length
        if pos_index >= start and (pos_index < (stop % length) or stop == 0):
            return True
        return False

    # https://tools.ietf.org/html/rfc1071
    # Parallel Summation
    def addCarryBits(w, n):
        mask = (1 << w) - 1            # 0xFFFF if w is 16
        while (n >> w):                # while more carry bits
            n = (n & mask) + (n >> w)  # TODO: might be wrong if the result is over 32 bits for 16 bit checksum
        return n

    # memo_f(msg, msg_id, msg_length, start, stop, fold_op):
    # calculate the checksum
    def calc(msg, msg_id, candidate_index, start, end, fold_op, final_op, magic_val):
        msg_len = msg_lens[msg_id]

        if fold_op == operator.xor:
            dict_op = fold_op
        else:
            dict_op = operator.add

        result = memo_f(msg, msg_id, msg_len, start, end, dict_op)

        # remove the checksum if it was in the payload:
        pos_index = candidate_index % msg_len
        if in_payload(candidate_index, start, end, msg_len):
            if fold_op == operator.xor:
                result = result ^ msg[candidate_index]
            else: # operator.add, operator.sub or onesComp
                result = result - msg[candidate_index]

        # transform addition result if fold_op is sub or onesComp
        if fold_op == operator.sub:
            result = -result
        if fold_op == onesComp:
            result = addCarryBits(width, result)

        if final_op is not None:
            if magic_val is None:
                    result = final_op(result)            # unary operation
            else:
                    result = final_op(result, magic_val) # binary operation

        # make sure it fits in width bits
        return result & ((1 << width) - 1)

    # returns True if the algorithm specified matches the value at candidate_index, False otherwise
    def check_algo(msg_start, msg_end, candidate_index, fold_op, final_op, magic_val):
        for msg_id, msg in enumerate(msgs):
            checksum = msg[candidate_index]
            algo_result = calc(msg, msg_id, candidate_index, msg_start, msg_end, fold_op, final_op, magic_val)
            if (checksum != algo_result):
                return False
        return True  

    def report_soln(entropy, msg_start, msg_end, candidate_index, fold_op, final_op, magic_val):
        magic_val = hex(magic_val) if magic_val is not None else None
        
        #print("entropy:", round(entropy, 3), "start:", msg_start, "end:", msg_end, "check:", candidate_index, fold_op, final_op, magic_val,function2label(fold_op))
        
        sol = ( round(entropy, 3), msg_start, msg_end,  candidate_index, fold_op, final_op, magic_val)
        return sol

    # make a list out of the messages
    def hexToList(data, pad):
        msgs = []
        if width == 8:

            for m in data.split("\n"):
                if pad and len(m) % 2 != 0:
                    m = m + "0"
                msgs.append([x for x in bytes.fromhex(m)])
        else: # it's 16
            #print("hexToList searching 16")
            for m in data.split("\n"):
                if pad and len(m) % 4 != 0:
                    m = m + (4 - (len(m) % 4)) * "0"
                msgs.append([int(m[i:i+4], 16) for i in range(0, len(m)-3, 4)])

        # print("Data")
        # print(data)
        # for m in msgs:
        #     print("\t",m)
        return msgs

    # Make a nice hex string
    def hexs(m):
        return " ".join(map(lambda b: format(b, "02x"), m))

    def twosComp(n):
        return -n

    def onesComp(n1, n2):
        mod = 1 << width
        result = n1 + n2
        return result if result < mod else (result + 1) % mod              


    def function2label(f):
        if f == twosComp:
            return "twosComp"
        if f == onesComp:
            return "onesComp"
        if f == operator.add:
            return "add"
        if f == operator.sub:
            return "sub"
        if f == operator.invert:
            return "invert"

        if f == operator.xor:
            return "xor"
        if f == None:
            return "None"
        return "unknown"

    # given a fold operation and a final operation, find a magic value that 
    # works for a particular message
    def getMagicVal(msg, msg_id, msg_start, msg_end, candidate_index, foldOp, finalOp):
        base = calc(msg, msg_id, candidate_index, msg_start, msg_end, foldOp, None, None)
        checksum = msg[candidate_index]

        mVal = finalOps[finalOp](checksum, base) % (1 << width)
        return mVal

    def create_msgs_list():

        if msgs == None:
            file_name = sys.argv[2]

            data = readexample(file_name)
        else:
            data = msgs
        data = cleanHex(data)
        return hexToList(data, True) # True = pad the messages

    def get_sorted_entropies():
        entropies = []
        for i in checksum_indices:
            checksum_values = []
            for m in msgs:
                checksum_values.append(m[i])
            entropies.append((i, H(checksum_values))) # a list of (index, entropy) tuples

        entropies.sort(key=lambda item: item[1], reverse=True)
        return entropies

    def full_search():
        if len(sys.argv) == 3:
            return False
        elif len(sys.argv) == 4 and sys.argv[3] == "-f":
            return True
        else:
            print("usage:", "sumeng3.py", "width", "data_file", "[-f]")
            sys.exit()

    # make a dictionary with the lengths of the messages
    def make_length_dict():
        msg_lens = dict()
        for msg_id in range(0, num_msgs):
            curr_msg = msgs[msg_id]
            msg_len = len(curr_msg)
            msg_lens[msg_id] = msg_len
        return msg_lens

    # we will need to run it with add and xor functions (msg_id, start, stop, function)
    def memo_f(msg, msg_id, msg_len, start, stop, dict_op):
        if dict_op == operator.xor:
            dd = xor_dd
        else: # dict_op is operator.add
            dd = add_dd

        tpl = (msg_id, start, stop)
        v = dd[tpl]

        if v == None:
            # base case - make sure start is always before stop
            if stop == start - msg_len + 1:
                dd[tpl] = msg[start]
            else:
                dd[tpl] = dict_op(msg[stop-1], memo_f(msg, msg_id, msg_len, start, stop-1, dict_op))
            return dd[tpl]
        else:
            return v

    # SETUP the constants we will use in the search:
    #    full_search
    #    width
    #    msgs
    #    msg_lens
    #    min_len 
    #    same_len
    #    foldOps
    #    finalOps
    #    checksum_indices
    #    num_msgs
    #    msg_lens
    #    dd

    #full_search = full_search() # false if we want to quit after finding the first solution, true otherwise
    full_search = True

    width = csumwidth
    assert(width == 8 or width == 16)


    msgs = create_msgs_list()


    msg_lens = set([len(m) for m in msgs])
    min_len = min(msg_lens)
    same_len = len(msg_lens) == 1

    if not same_len:
        msgs.sort(key=len) # check incorrect algorithms on the shortest examples first

    # options for functions that will be passed to the reduce function
    foldOps = [operator.xor, operator.add, operator.sub, onesComp]
    #foldOps = [operator.xor, operator.add, onesComp]
    # final operation options- key is the operation, value is the inverse (unary operations have no inverse)
    finalOps = {None: None, twosComp: None, operator.invert: None, operator.add: operator.sub, operator.xor: operator.xor}

    # search both directions if messages are variable lengths
    if (same_len):
        checksum_indices = range(0, min_len)
    else:
        checksum_indices = range(-min_len, min_len)

    # delete checksum indices that have the same value across all messages 
    checksum_indices = [i for i in checksum_indices if checkpatch(i)]
    #checksum_indices = range(-1, 0)

    entropies = get_sorted_entropies() # a list of (index, entropy) tuples sorted by entropy

    num_msgs = len(msgs)
    msg_lens = make_length_dict() # key is msg_id, value is length of message

    # default dictionaries for dynamic programming
    add_dd = defaultdict(lambda:None)
    xor_dd = defaultdict(lambda:None)

    def search_binary_finalOp(start, end, candidate_index, foldOp, finalOp, entropy):
        mVals = set()
        for i, m in enumerate(msgs):
            # determine a magic value for a message and then see if it holds                     
            mVal = getMagicVal(m, i, start, end, candidate_index, 
                                foldOp, finalOp) # finalOps[finalOp] = inverse function 
            mVals.add(mVal)

            if len(mVals) > 1: # found a contraction
                mVals.clear()
                return None
            if i == num_msgs - 1: # found a solution
                sol = report_soln(entropy, start, end, candidate_index,  foldOp, finalOp, mVal)
                mVals.clear()
                return sol

    def search_unary_finalOp(start, end, candidate_index, foldOp, finalOp, entropy):
        if check_algo(start, end, candidate_index, foldOp, finalOp, None):
            sol = report_soln(entropy, start, end, candidate_index,  foldOp, finalOp, None)
            # if full_search == False:
            #     sys.exit()
            return sol
        return None


    def measure_payload_ratio(msgs,start,end):
        tot_sliced = 0
        tot = 0
        for m in msgs:
            s = slice(m,start,end)
            tot_sliced+=len(s)
            tot+=len(m)

        return tot_sliced/(1.0*tot)


    def rank_sols(sols):
        max_ent = max([s[0] for s in sols])
        max_perc = max([s[-1] for s in sols])

        ranked_sols = [s for s in sols if s[0]==max_ent]
        ranked_sols = sorted(ranked_sols,key=lambda x:x[-1],reverse=True)
        return ranked_sols

    def sol2dict(sol):
        keys = [k.strip() for k in "entropy , msg_start, msg_end,  candidate_index, fold_op, final_op, magic_va, payload_ratio ".split(",")]
        [entropy , msg_start, msg_end,  candidate_index, fold_op, final_op, magic_va, payload_ratio]  = sol
        
        sol = list(sol)
        sol[4] = function2label(sol[4])
        sol[5] = function2label(sol[5])

        res = {}
        for i,k in enumerate(keys):
            res[k]= str(sol[i])
        return res


    def compareSols(output_,goal):

        output = sol2dict(output_)

        for key in goal.keys():
            if str(goal[key]).lower() != str(output[key]).lower():
                return False
        return True

    def search():
        counter = []
        for pairs in entropies:
            
            candidate_index = pairs[0]
            entropy = pairs[1]

            for msg_start in range(0, min_len):
                for msg_end in reversed(range(msg_start-min_len+1, 1)):
                    #print("candidate_index",candidate_index,"msg_start",msg_start,"msg_end",msg_end)
                    payload_ratio = measure_payload_ratio(msgs,msg_start,msg_end)
                    # skip if the entire message is just the candidate checksum
                    if (msg_start-min_len+1 == msg_end and msg_start == candidate_index % min_len):
                        continue

                    # check all combinations of fold operations, final operations, and magic values
                    for foldOp in foldOps:
                        for finalOp in finalOps.keys():
                            if finalOps[finalOp] is not None: # it's a binary final operation
                                sol = search_binary_finalOp(msg_start, msg_end, candidate_index, foldOp, finalOp,entropy)
                            else: # unary operation
                                sol = search_unary_finalOp(msg_start, msg_end, candidate_index, foldOp, finalOp,entropy)
                            if sol != None:
                                sol+=(payload_ratio,)
                                counter.append(sol)
        #print("Solutions Found:",len(counter))
        #print("Format: entropy, msg_start, msg_end, candidate_index, foldOp, finalOp,payload_ratio")
        results = []
        if len(counter) > 0 :
            
            counter = sorted(counter,key=lambda x:x[-1],reverse=True)
            for sol in rank_sols(counter):
                # print(sol)
                # print("\t",sol2dict(sol))
                if goal != None:
                    #print(compareSols(sol,goal),sol)
                    results.append((compareSols(sol,goal),sol))
                else:
                    #print(sol)
                    results.append((None,sol))
        return results
    return search()



if __name__ == "__main__":
    from corpus import examples
    for example in examples:
        
        msgs,sol,lbl = example
        #sumeng(msgs=example1_msgs,goal=example1_sol)
        print("-"*80)
        print("Test Case",lbl)
        res = sumeng(msgs=msgs,goal=sol)
        # for r in res:
        #     print(r)
        #print("Total Solutions",len(res))
        if len(res) > 0:
            sol_index = min([i for i in range(len(res)) if res[i][0]==True])
            print("Sols which use 100% of messages:",len([r for r in res if r[1][-1]==1.0]))
            if sol_index != []:
                rank = 1-(sol_index/(1.0*len(res)))
                print("Goal Solution Index",sol_index,"Rank",round(rank,2),"Percent of Message Used",round(res[sol_index][1][-1],2))





#goal = { 'msg_start': '0', 'msg_end': '0', 'candidate_index': '1', 'fold_op': 'onesComp', 'final_op': 'invert', 'magic_va': 'None', }
#sumeng(example1_msgs)