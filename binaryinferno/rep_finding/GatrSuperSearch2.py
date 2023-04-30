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

# Do that pattern search


import time
from collections import defaultdict

from Rules import leadingZerosCheck,getrules #,rules_lzf

if False:
    from Rules import rules,  leadingZerosCheck,rules_star_pairs,rules_star_ids,rules_lzf
    rules_names = [r[0] for r in rules]
    rules_funcs = [r[1] for r in rules]


    rules_le,rules_names_le,rules_funcs_le,rules_star_pairs_le,rules_star_ids_le
if False:
    rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids,rules_lzf =getrules(RULEENDIAN)
    for r in rules_names:
        print(r)


# ---------------------------
# Enropy calculation function
#
def H(xs):
    from collections import Counter
    import math
    if len(xs[0])==0:
        return 0
    qty = Counter(xs)
    n = len(xs)*1.0
    tot = 0.0
    for pv in qty:
        v = qty[pv]*1.0
        p =(v/n)
        assert(p<=1)
        #if p == 1.0:
        #    return 0
        if p>=0:
            tot += (p * math.log(p,2))
    return abs(-tot)

def preH(xs):
    return H([str(x[:3]) for x in xs])

def supersearch(msgs,args,offset=0,dumpfunction=None,RULEENDIAN="any",filterrules=None):

    from collections import defaultdict
    dumpedsols = defaultdict(lambda:False)

    if filterrules != None:
        if filterrules == "BE":
            filterrulelabel = "little"
        if filterrules == "LE":
            filterrulelabel = "big"
        if filterrules == "XE":
            filterrules = None


    if False:
        from Rules import rules,  leadingZerosCheck,rules_star_pairs,rules_star_ids,rules_lzf
    print("")
    print("USING ENDIANESS",RULEENDIAN)
    print("")
    rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids,rules_lzf =getrules(RULEENDIAN)

    # This is where we'd overwrite our rules to use only BE or LE rules
    # from Rules import rules_be as rules
    # from Rules import rules_star_pairs_be as rules_star_pairs
    # from Rules import rules_star_ids_be as rules_star_ids

    # rules_names = [r[0] for r in rules]
    # rules_funcs = [r[1] for r in rules]


    facts = {}

    for v in args:
        facts[v] = args[v]
        #print(v,args[v])
    #facts["samples"] = 32
    #facts["maxhyplen"] = 10
    #facts["qtysols"] = 1

    OFFSET = offset
    BYTE_RULE_ID = len(rules)-1 # we make it the last ID by convention
    for i in range(len(rules)):
        if "VQFW_" in rules_names[i]:
            VQFW_RULE_ID = i
            break

    MEMOMODE    = True
    SORTED      = True #True

    import random
    random.seed(1)

    SAMPLES = facts["ARG_samples"]
    MAXHYPLEN = facts["ARG_maxhyplen"]
    MAXSOLS     = facts["ARG_qtysols"]
    try:
        SHORTCIRCUIT = facts["ARG_shortcircuit"]
    except:
        print("Shortcircuit not defined, will not shortcircuit")
        SHORTCIRCUIT = None

    #msgs = [m for m in msgs if len(m) > 20]
    if SORTED:
        msgs = sorted(msgs,key=lambda x:len(x))

    full_msgs = msgs
    msgs = msgs[:SAMPLES]

    #msgs = [[random.randrange(0,256) for i in range(20)]+m for m in msgs]

    facts["PE"] = []

    facts["STAT_Counter"] = 0
    facts["STAT_Counter_Hit"] = 0
    facts["STAT_Counter_Hit_Byte"] = 0
    facts["STAT_Counter_Miss"] = 0
    facts["STAT_max_pat_len"] = 0


    STAT_min_sample_len = min([len(m) for m in msgs])
    STAT_max_sample_len = max([len(m) for m in msgs])
    STAT_avg_sample_len = int(sum([len(m) for m in msgs])/len(msgs))

    facts["STAT_min_sample_len"] = STAT_min_sample_len
    facts["STAT_max_sample_len"] = STAT_max_sample_len
    facts["STAT_avg_sample_len"] = STAT_avg_sample_len


    MAXHYPLEN   =  min([MAXHYPLEN,STAT_min_sample_len])



    facts["PARAM_MEMOMODE"] = MEMOMODE
    facts["PARAM_SORTED"] = SORTED
    facts["PARAM_MAXHYPLEN"] = MAXHYPLEN

    facts["STAT_tm"] = time.time()

    from collections import defaultdict

    memos = defaultdict(lambda:None)

    # Leading zero memos
    memos_lz = defaultdict(lambda:False)


    # memos = []

    # for rule_id in range(len(rules)):
    #   rs = []
    #   for m in msgs:
    #       xs = [None for i in range(len(m))]
    #       rs.append(xs)
    #   memos.append(rs)


    memo_puts = []
    #
    # Build memos
    # [msg] -> memo 
    #
    # Apply a function which takes 
    #


    def msg2edges(memos):

        # Python program to find articulation points in an undirected graph 
           
        from collections import defaultdict 
           
        #This class represents an undirected graph  
        #using adjacency list representation 
        class Graph: 
           
            def __init__(self,vertices): 
                self.V= vertices #No. of vertices 
                self.graph = defaultdict(list) # default dictionary to store graph 
                self.Time = 0
           
            # function to add an edge to graph 
            def addEdge(self,u,v): 
                self.graph[u].append(v) 
                self.graph[v].append(u) 



            '''A recursive function that find articulation points  
            using DFS traversal 
            u --> The vertex to be visited next 
            visited[] --> keeps tract of visited vertices 
            disc[] --> Stores discovery times of visited vertices 
            parent[] --> Stores parent vertices in DFS tree 
            ap[] --> Store articulation points'''
            def APUtil(self,u, visited, ap, parent, low, disc): 
          
                #Count of children in current node  
                children =0
          
                # Mark the current node as visited and print it 
                visited[u]= True
          
                # Initialize discovery time and low value 
                disc[u] = self.Time 
                low[u] = self.Time 
                self.Time += 1
          
                #Recur for all the vertices adjacent to this vertex 
                for v in self.graph[u]: 
                    # If v is not visited yet, then make it a child of u 
                    # in DFS tree and recur for it 
                    if visited[v] == False : 
                        parent[v] = u 
                        children += 1
                        self.APUtil(v, visited, ap, parent, low, disc) 
          
                        # Check if the subtree rooted with v has a connection to 
                        # one of the ancestors of u 
                        low[u] = min(low[u], low[v]) 
          
                        # u is an articulation point in following cases 
                        # (1) u is root of DFS tree and has two or more chilren. 
                        if parent[u] == -1 and children > 1: 
                            ap[u] = True
          
                        #(2) If u is not root and low value of one of its child is more 
                        # than discovery value of u. 
                        if parent[u] != -1 and low[v] >= disc[u]: 
                            ap[u] = True    
                              
                        # Update low value of u for parent function calls     
                    elif v != parent[u]:  
                        low[u] = min(low[u], disc[v]) 
          
          
            #The function to do DFS traversal. It uses recursive APUtil() 
            def AP(self): 
           
                # Mark all the vertices as not visited  
                # and Initialize parent and visited,  
                # and ap(articulation point) arrays 
                visited = [False] * (self.V) 
                disc = [float("Inf")] * (self.V) 
                low = [float("Inf")] * (self.V) 
                parent = [-1] * (self.V) 
                ap = [False] * (self.V) #To store articulation points 
          
                # Call the recursive helper function 
                # to find articulation points 
                # in DFS tree rooted with vertex 'i' 
                for i in range(self.V): 
                    if visited[i] == False: 
                        self.APUtil(i, visited, ap, parent, low, disc) 
                retval = []
                for index, value in enumerate (ap): 
                    if value == True: 
                        #print(index )
                        retval.append(index)

                return retval

            '''A recursive function to print all paths from 'u' to 'd'. 
            visited[] keeps track of vertices in current path. 
            path[] stores actual vertices and path_index is current 
            index in path[]'''
            def printAllPathsUtil(self, u, d, visited, path): 
          
                # Mark the current node as visited and store in path 
                visited[u]= True
                path.append(u) 
                retval = []
                # If current vertex is same as destination, then print 
                # current path[] 
                if u ==d: 
                    print(path)
                else: 
                    # If current vertex is not destination 
                    #Recur for all the vertices adjacent to this vertex
                    if True: #len(path) < 25: 
                        for i in self.graph[u]: 
                            if visited[i]==False: 
                                self.printAllPathsUtil(i, d, visited, path) 
                              
                # Remove current vertex from path[] and mark it as unvisited 
                path.pop() 
                visited[u]= False
           
           
            # Prints all paths from 's' to 'd' 
            def printAllPaths(self,s, d): 
          
                # Mark all the vertices as not visited 
                visited =[False]*(self.V) 
          
                # Create an array to store paths 
                path = [] 
          
                # Call the recursive helper function to print all paths 
                self.printAllPathsUtil(s, d,visited, path)
            # Use BFS to check path between s and d 
            def isReachable(self, s, d): 
                # Mark all the vertices as not visited 
                visited =[False]*(self.V) 
           
                # Create a queue for BFS 
                queue=[] 
           
                # Mark the source node as visited and enqueue it 
                queue.append(s) 
                visited[s] = True
           
                while queue: 
          
                    #Dequeue a vertex from queue  
                    n = queue.pop(0) 
                      
                    # If this adjacent node is the destination node, 
                    # then return true 
                    if n == d: 
                        return True
          
                    #  Else, continue to do BFS 
                    for i in self.graph[n]: 
                        if visited[i] == False: 
                            queue.append(i) 
                            visited[i] = True
                # If BFS is complete without visited d 
                return False


##################################################################


        
        edge_list = []
        landing = defaultdict(lambda:None)

        inbound = defaultdict(lambda:[])
        outbound = defaultdict(lambda:[])
        msg_id = 0
      


        def criticalNodes(msg_id):
            msg = msgs[msg_id]
            g1 = Graph(len(msg)+1) 

            for index in range(len(msg)):
                for rule_id in range(len(rules)):
                    v = memos[msg_id,index,rule_id]
                    if v != None:
                        if rules_names[rule_id] != "BYTE":
                        #if True:
                            edge_list.append((rule_id,index,len(msg)-len(v),len(v)))
                            #print(edge_list[-1])
                            landing[index] = len(msg)-len(v)
                            inbound[msg_id,index]+= [rule_id ]
                            outbound[msg_id,len(msg)-len(v)]+= [rule_id]
                            g1.addEdge(index,len(msg)-len(v))



       
            
            critical = g1.AP() 
            #print(msg_id,critical)
            return critical

        def connected(msg_id,exc):
            msg = msgs[msg_id]
            g1 = Graph(len(msg)+1) 

            for index in range(len(msg)):
                for rule_id in range(len(rules)):
                    v = memos[msg_id,index,rule_id]
                    if v != None:
                        if rules_names[rule_id] not in exc:
                        #if True:
                            g1.addEdge(index,len(msg)-len(v))
            return g1.isReachable(0,len(msg))

        for msg_id in range(len(msgs)):
            # test for critical nodes

            # try:
            # #if True:
            #     cn = criticalNodes(msg_id)
            #     print(msg_id,len(msgs[msg_id]),len(cn))
            #     if len(cn) >= 1:
            #         cn_v = cn[0]
            #         in_rule_id = inbound[msg_id,cn_v]
            #         out_rule_id = outbound[msg_id,cn_v]
            #         # if in_rule_id and out_rule_id:
            #         #     if in_rule_id:
            #         #         print("---> inbound",[in_rule_id])
            #         #     if out_rule_id:
            #         #         print("---> outbound",[out_rule_id])
            # except:
            #     print(msg_id,"failed")

            for r in rules_names:
                rule_test = [r,'BYTE']
                cv = connected(msg_id,rule_test)
                if not cv:
                    print(msg_id,"connected for ",r,":",cv,rule_test)
        #g1.printAllPaths(0, len(msg))
        #print("gt",gt)
        print("QTY EDGES",len(edge_list))
        for e in edge_list:
            (rule_id,start,end,idx_from_end) = e
            #if landing[end] != None:
            #    print(e)



    def buildmemos(msgs,memos):

    #if True:
        for msg_id in range(len(msgs)):
            msg = msgs[msg_id]
            for index in range(len(msg)):

            # THis should change our memoization to restrict to only going as deep as the shortest mst. 
            #for index in range(min([len(m) for m in msgs])+1):
                
                for rule_id in range(len(rules)):

                    f = rules_funcs[rule_id]
                    
                    # We are giving it a list of one message.

                    xs = f([msg[index:]])
                    
                    #print("buulding memos",rule_id,msg_id,index,xs)
                    
                    if xs != None:

                        # Hack because it returns a list? and we are only giving it a single element
                        v = xs[0] # <-- This is the remaining bytes in the message after the rule is applied, or none. 

                        if v != []:
                            lz = xs[0][0]==0 #<--- possible problem as this only checks if the first thing is zero
                        else:
                            lz = False
                    else:
                        v = None
                        lz = False

                    # # added [None in xs] ofr possible new rules
                    # # Need to double check this
                    # if xs == None or [None in xs]:
                    #   v = None
                    # else:
                    #   v = xs[0]
                    #   v= xs

                    #print("memo insert",msg_id,index,rule_id,xs[0])
                    #memos[msg_id,index,rule_id] = xs[0]
                    
                    #memos[rule_id][msg_id][index] = v

                    memos[msg_id,index,rule_id] = v
                    memos_lz[msg_id,index,rule_id] = lz

                    # if "3LVbig" in rules_names[rule_id]:
                    #     print(rules_names[rule_id],msg_id,index,"v",v,"lz",lz)
                    #memo_puts.append((rule_id,msg_id,index,xs,v))


        # ******************************************************************************************
        # lv*
        # tlv*
        if False:
            lvstar_rule_id= rules_names.index("lv*")


        # Here's where we store 
        lvstar_f = defaultdict(lambda:set())

        # Don't use this
        lvstar_f_cache = defaultdict(lambda:None)


        # For regular pattern we care about... build our set based memoization
        for rule_id,star_id in rules_star_pairs: #range(len(rules)):
            for msg_id in range(len(msgs)):

                #Get the message
                msg = msgs[msg_id]

                # Get indexes into the message from the back to the front. e.g 4,3,2,1
                # Gives us optimal substructure

                indexes = [i for i in range(len(msg))][::-1]

                for index in indexes:

                    if False:
                        # Lookup the function     
                        f = rules_funcs[rule_id]
                    
                        # We are giving it a list of one message.
                        current_index= len(msg)

                        #xs = f([msg[index:]])
                        ys = memos[msg_id,index,rule_id]

                    # We keep track of our destinations in positions relative to the back

                    back_index = len(msg)-index

                    #print("msg_id",msg_id,"index",back_index,msg[index:],memos[msg_id,index,rule_id])

                    # Get the pattern's memoized result
                    xs = memos[msg_id,index,rule_id]

                    # If it wasn't a location for a valid application of the pattern
                    if xs == None:
                        #lvstar_f[msg_id,back_index,rule_id] = set([back_result_index])

                        # Then the * version of the rule could get to this position
                        lvstar_f[msg_id,back_index,rule_id] = set([back_index])
                        #print("\tNone\t",back_result_index)
                    # If it was a valid location for an application
                    else:
                        
                        # How much deeper could we get after the application? 
                        back_result_index = len(xs)

                        # We could get to whereever we ended up, plus wherever we could go from there.
                        result = set([back_result_index]).union(lvstar_f[msg_id,back_result_index,rule_id])

                        #print("\tOk\t",result)

                        # Store where we could reach in the star memos
                        lvstar_f[msg_id,back_index,rule_id] = result
                    

        # Populate the memos with our data from the star_memos   
        # use the original rule_id       
        for rule_id,star_id in rules_star_pairs:# [2]: #range(len(rules)):
            for msg_id in range(len(msgs)):
                msg = msgs[msg_id]
                for index in range(len(msg)):
                    back_index = len(msg)-index
                    #print("*msg_id",msg_id,"index",back_index,msg[index:],lvstar_f[msg_id,back_index,rule_id])

                    v = lvstar_f[msg_id,back_index,rule_id]

                    memos[msg_id,index,star_id] = v

                # For 0 applications, we patch in a -1 index at the end as a sentinel value
                memos[msg_id,len(msg),star_id] = set([-1])

        if False: 
            for rule_id in [2]:
                for index in range(min([len(m) for m in msgs])):

                    sets = [lvstar_f[msg_id,len(msgs[msg_id])-index,rule_id] for msg_id in range(len(msgs))]
                    u = set.intersection(*sets)
                    for msg_id in range(len(msgs)):
                        back_index = len(msgs[msg_id])-index
                        print(index,msg_id,lvstar_f[msg_id,back_index,rule_id])

                    print("u",u)

            for msg in msgs:
                print(msg)

            #print("lv* index",rules_names.index("lv*"))
        #quit()
        if False:
            for rule_id in range(len(rules)):
                rule_sum = []
                for msg_id in range(len(msgs)):
                    msg = msgs[msg_id]
                    def xx (xs):
                        if xs == None:
                            return -1
                        else:
                         return len(xs)
                    # If we have a -1 it means the rule couldn't be applied at this location
                    xs = [xx(memos[msg_id,index,rule_id]) for index in range(len(msg))]

                    # if "LLLVbig_3" in rules_names[rule_id]:
                    #     print("memo ret","msg",msg_id,"idx",index,xs)

                    # if we have any entries here, then the rule can be applied to this message
                    xs = [x for x in xs if x >= 0]

                    rule_sum.append(len(xs)) # <- Number of places we can apply this rule and places we can get to.  
                    # if "LLLVbig_3" in rules_names[rule_id]:
                    #     print("rule_id",rule_id,"msg_id",msg_id,"xs",xs,"rule_Name",rules_names[rule_id])
                #print(rule_id,rules_names[rule_id],len(rule_sum),len([r for r in rule_sum if r > 0]),len(rule_sum)==len([r for r in rule_sum if r > 0]),min([r for r in rule_sum if r > 0]),rule_sum)
                try:
                    print(rule_id,rules_names[rule_id],"len rule sum",len(rule_sum),rule_sum,len([r for r in rule_sum if r > 0]),len(rule_sum)==len([r for r in rule_sum if r > 0]),min([r for r in rule_sum if r > 0]))
                except:
                    print("Line 741, something broke for rule_id",rule_id )
                #print("---")

        #msg2edges(memos)
        return memos
        
    memos = buildmemos(msgs,memos)
    
    # See the state of memos 
    # for rule_id,v in enumerate(rules_names):
    #     for msg_id in range(len(msgs)):
    #         print(msg_id,rule_id,v,memos[msg_id,1,rule_id],"\t",msgs[msg_id])
    #     print("")

    print("Memos done")

    # zs are tails
    def getmemos(zs,rule_id):
        res = []
        if MEMOMODE:
            rule_name = rules_names[rule_id]
            # if "*" in rules_names[rule_id]:
            #     print("getmemos",rules_names[rule_id],[len(z) for z in zs])
            #     for z in zs:
            #         print("\t",z)
            if False:

                if (leadingZerosCheck(zs)) and (rule_name in ["VQVL","QTLV","LV"] or "VQFW" in rule_name):
                    return None
                if "4LV" in rule_name and leadingZerosCheck(zs,4):
                    return None
                elif "3LV" in rule_name and leadingZerosCheck(zs,3):
                    return None
                elif "2LV" in rule_name and leadingZerosCheck(zs,2):
                    return None
                elif "4Q" in rule_name and leadingZerosCheck(zs,4):
                    return None
                elif "3Q" in rule_name and leadingZerosCheck(zs,3):
                    return None
                elif "2Q" in rule_name and leadingZerosCheck(zs,2):
                    return None
                elif "lv*" == rule_name and leadingZerosCheck([z for z in zs if z!=[]],1):
                    return None

 
            # Doing leading zeros stuff 
            if True:

                lzf = rules_lzf[rule_name]

                # If this is a star rule, we need to get the lzf differently
                if "*" in rule_name:
                    lzf = rules_lzf[rule_name[:-1]]

                # If there's a lzf for this rule...
                if lzf != None:

                    # Call the lzf to get the portion we care about it
                    lzf_res = [lzf(z) for z in zs]
                    #print("\tlzf_res",rule_name,lzf_res)

                    # Couldn't get all the bytes we needed
                    # Unless we are a star pattern, then it's ok
                    if [] in lzf_res and "*" not in rule_name:
                        return None 

                    # if we called it for only one thing (a single message)    
                    if len(lzf_res) == 1:
                        #return None
                        pass
                    else:
                        # Is everything  the same 
                        #print(rule_name,"everything the same",all([x==lzf_res[0] for x in lzf_res[1:]]),lzf_res)
                        if all([x==lzf_res[0] for x in lzf_res[1:]]):
                            # print("\tNone on all")
                            # print("")
                            return None

                else:
                    #print("No LZF for",rule_name)
                    pass


                # Do a smart LV* leading zeros check... basicallt, remove the []'s


            #if (rule_name in ["VQVL","TLV"] or "VQFW" in rule_name):
            # else:
            #     if rule_name != "BYTE":
            #         lz = True
            #         for msg_id in range(len(zs)):
            #           lz = lz and memos_lz[msg_id,len(zs[msg_id]),rule_id]
            #         if lz:
            #           return None

        #print("eval rule_id",rule_id)
        for msg_id in range(len(zs)):
            orig_msg = msgs[msg_id] # Original = xs = ys + zs
            msg      = zs[msg_id]   # Our current position in the original message (the tail)
            back_index   = len(orig_msg)-len(msg) # Orig len = 100, new msg len = 20, index must be 80 

            # a b c d e f g (7)
            #       d e f g (4)
            # back_index = 3

            #print("memo retrieve",msg_id,index,rule_id,memos[msg_id,index,rule_id])

            # We got a [] as a msg, if all zs where [] we would have noted it somehow, so must be a bad application
            # You can't apply anything to a [], so fail. 

            # If we are using regular rules, we can't go off the ends
            # for lv* rule we can go off the end
            if msg == [] and rule_id not in rules_star_ids:
                #print("got a [] trying to apply",rules_names[rule_id],"to",zs,msg)
                res.append(None)
                
                return None
            else:
                #v = memos[msg_id,index,rule_id]
                #v = memos[rule_id][msg_id][index]



                v= memos[msg_id,back_index,rule_id]

                # if (rule_id,msg_id,index) not in memo_puts:
                #   #print("ERROR: ",(rule_id,msg_id,index),msg)
                #   pass

                # Rule couldn't apply, return None.
                if v is None:
                    return None
                res.append(v)

        # here's all the fancy rule* logic
        if rule_id in [x[1] for x in rules_star_pairs]:
            #print("getmemos star rules",rules_names[rule_id],[len(z) for z in zs],res)
            #print(rules_names[rule_id],"starruleres",res,len(set([len(r) for r in res]))==1)
            # is there a consistent hypothesis? 
            # if so, what the result of applying it?

            # identify any 0 applications, 
            # look for consistent applications / 0 applications

            # Wildscoops 

            # 00 01ff       02ee ee
            # 00 03ffffff   01ee 

            #print("")
            #print("lvstar rule ",rule_id,res,"for msgs")
            # for m in zs:
            #     print("\t",m)
            #return None
            # for z in zs:
            #     print("\t",z)
            #print("lv* res",res,set.intersection(*res))
            #return None


            # This is supposed to be short circuiting detecting LV as LV* 
            # res:  [set([int])]
            if len(set([len(r) for r in res]))==1:
                return None


            # Did we find a -1, if so then we are off the edge, only lv* is allowed to do this
            if set([-1]) in res:

                # Remove the -1 (end of message sentinel)
                xres = [r for r in res if r != set([-1])]
                # Find a consistent end index across all the remaining results
                res_index = set.intersection(*xres)
            # We didn't look off the edge (there are no 0 quantity applications of the rule)

            else:
                # Find a consistent end index across all the results
                res_index = set.intersection(*res)


            # The resulting index is not empty set, so we have a consistent end index.
            if res_index != set():

                min_from_tail = min(res_index.difference(set([-1])))

                # filter in case pat would also match where pat*
                trim_res = [[v for v in list(r) if v >= min_from_tail] for r in res]
                #print("trim_res",trim_res)
                if len(set([len(r) for r in trim_res]))==1:
                    return None

                #print("min from tail",min_from_tail)
                # Turn this value in lambda xs: xs[-min_from_tail:]
                if min_from_tail == 0:
                    new_res = [[] for i in range(len(zs))]
                else:

                    new_res = []
                    for msg_id in range(len(zs)):
                        orig_msg = msgs[msg_id]
                        if res[msg_id] == set([-1]):
                            #print("ofund a -1",orig_msg,zs[msg_id])
                            #new_res.append(orig_msg)
                            new_res.append(zs[msg_id])
                        else:
                            new_res.append(orig_msg[-min_from_tail:])

                # print("zs")
                # for z in zs:
                #     print("\t",z)
                # print("new_res")
                # for z in new_res:
                #     print("\t",z)

                # print("No change",zs == new_res)
                if zs == new_res:
                    return None
                #return None

                # If we have a star pattern solution, we can get to the end, we will 
                # add the byte patterns which take place after this rule when we record the solution
                return ([[] for i in new_res],min_from_tail)
                return (new_res,min_from_tail)

            # If the offsets from end of messages are the empty set, then we didn't find a consistent position
            # Thus the rule cannot be applied.
            else:
                return None





        #print("rule_id",rule_id,res)
        return res

    # Code to look for better starts 
    # valids = []   
    # for k in range(min([len(m) for m in msgs])):
    #     print("k",k)
    #     short_msgs = [m[k:] for m in msgs]
    #     for rule_id in range(len(rules)):
    #         r = getmemos(short_msgs,rule_id)
    #         if r != None:
    #             valids.append((k,rules_names[rule_id],[s[0] for s in short_msgs]))

    # for v in valids:
    #     print(v)
    

    import sys

    from collections import Counter


    # Cache functions 
    qty = Counter()

    memo_f = defaultdict(lambda:False)
    memo_f_cache = defaultdict(lambda:None)




    def cache_f(f,p,msgs):

        # p = rule_id
        # Have we looked up this p (rule_id) , with these offsets before? 
        key = str([p] +[len(x) for x in msgs])

        # If we have a cached value, use it
        if memo_f[key]:
            return memo_f_cache[key]

        # If no cached value, calculate it
        else:

            # Keep track of cache misses
            qty[key]+=1

            # If we are using the memos
            if MEMOMODE:
                r = getmemos(msgs,p)
            # Otherwise run the function
            else:
                r = f(msgs)

            # Cache the result
            memo_f_cache[key] = r

            # Record that we have a cached value
            memo_f[key] = True
            return r

    #print("="*80)
    if False:
        res = cache_f(None,lvstar_rule_id,msgs)
        res = getmemos(msgs,lvstar_rule_id)
    
        for i in range(min([len(m) for m in msgs])):
            xmsgs = [m[i:] for m in msgs]
            for m in xmsgs:
                print("-->",m)
            res = getmemos(xmsgs,lvstar_rule_id)
        
            print("res",i,res)
            print("")


    #print("-"*80)
    if False:
        for i in range(min([len(m) for m in msgs])+1):
            for msg_id in range(len(msgs)):
                msg = msgs[msg_id][i:]
                back_index = len(msgs[msg_id]) - len(msg)
                print("index",i,"msg_id",msg_id,memos[msg_id,i,lvstar_rule_id],msgs[msg_id][i:])
            print("-")
        #quit()

    # Given a set of old,msgs, and new msgs, get the stuff removed from old to make new
    def chomp(old_msgs,new_msgs):
        res = []
        for i,msg in enumerate(old_msgs):
            old_msg = msg
            new_msg = new_msgs[i]
            end_index = len(old_msg)-len(new_msg)
            res.append(old_msg[:end_index])

        return res


    # search: [msg] --> sols
    #   calls getmemos : [rule_type::msg],rule --> [msg] option
    #           back_index = len(orig_msg)-len(msg)
    #           this is the offset from the front ABCDEF --> CDEF = 2 len(ABCDEF) 6 - len(CDEF) 4 = 2
    #           looksup: memos[msg_id,back_index,rule_id]

    def search(msgs,MAXHYPLEN,OFFSET,SHORTCIRCUIT=None):

        tm_start = time.time()

        solutions   = []
        stack       = []
        init_sol = []
        byte_rule_id = rules_names.index("BYTE")

        # If we are offsetting into the messages
        if OFFSET >0:
            
            init_sol = [byte_rule_id for i in range(OFFSET)]
            msgs = [m[OFFSET:] for m in msgs]

        if SHORTCIRCUIT != None:
            if OFFSET > 0:
                shortcircuit_sol = init_sol + [byte_rule_id for i in range(SHORTCIRCUIT)]
            else:
                shortcircuit_sol = [byte_rule_id for i in range(SHORTCIRCUIT)]
        else:
            shortcircuit_sol = []


        # if OFFSET >0:
            
        #     #init_sol = [byte_rule_id for i in range(OFFSET)]
        #     #msgs = [m[OFFSET:] for m in msgs]
        #     if SHORTCIRCUIT != None:
        #         shortcircuit_sol = init_sol + [byte_rule_id for i in range(SHORTCIRCUIT)]  
        #     else:
        #         shortcircuit_sol = []
        #     #msgs = [m[OFFSET:] for m in msgs]
        #     #print("init_sol",init_sol)
        # else:
        #     if SHORTCIRCUIT != None:
        #         shortcircuit_sol = [byte_rule_id for i in range(SHORTCIRCUIT)] 
        #     else:
        #         shortcircuit_sol  = []

        stack.append( (msgs,init_sol,-1,[]) )

        while stack != []:
            
            (msgs,pats,prev,msg_chunks) = stack.pop()

            # print("MAXHYPLEN",MAXHYPLEN)
            # print("OFFSET",OFFSET)
            
            # print("SHORTCIRCUIT",SHORTCIRCUIT)
            # print("shortcircuit_sol",len(shortcircuit_sol))
            # print("pats",len(pats))
            # print("pats",[rules_names[r] for r in pats])

            # print("")
            # Could cut out that MAX Sols check and when I find a sol, do it. 
            #if len(pats) > MAXHYPLEN or len(solutions)>=MAXSOLS:
            if len(pats) > MAXHYPLEN:
                    #p = prev+1
                #print("passing",pats,solutions,MAXSOLS)

                continue
            if True and SHORTCIRCUIT != None and pats == shortcircuit_sol:
                print("We have hit the shortciruit, bailing")
                return solutions
                continue
            #facts["STAT_max_pat_len"] = max(len(pats),facts["STAT_max_pat_len"])
            #print("stackh",len(stack),prev)
            # print("="*30)
            # print("In state",[rules_names[p] for p in pats])
            # print("-"*30)
            # for m in msgs:
            #     print(m)


            while prev < len(rules_funcs)-1 :


                # Hack for time
                # if time.time() - facts["STAT_tm"] > 30:
                #     return solutions
                #print("prev",prev)
                facts["STAT_Counter"]+=1
                p = prev+1

                if filterrules != None and filterrulelabel in rules_names[p]:
                    prev+=1
                    continue

                # Allow tlv*, but not just tlv. we have no reason to assume the tag byte, we can just infer the length value pair and go on.
                if "*" not in rules_names[p]:
                    rn =rules_names[p][:2]
               
                    if "1T" == rn or "2T" == rn or "3T" == rn:
                        prev+=1
                        continue

                f = rules_funcs[p]
                #print(p,rules_names[p],f)

                # if len(pats) > 10 or len(solutions)>=MAXSOLS:
                #     #p = prev+1
                #     print("passing",pats,solutions,MAXSOLS)
                #     prev = p
                #     continue
                    #return solutions
            
                # Here's where we go and get the result of applying rule P
                metadata = None
                rs = getmemos(msgs,p)
                if type(rs)==type(()):
                    metadata = rs[1]
                    rs = rs[0] # <--- Need to make sure * pats to end dont create 0 width intervals

                #r = rules_funcs[p](msgs)


                #print("\twith",[rules_names[p] for p in pats],"For Rule",p,rules_names[p],"-->",rs)

                # if rs != None:
                #     for i,m in enumerate(msgs):
                #         print("\t\t",m,"-->",rs[i])


                # if p in [3]:
                #     for m in msgs:
                #         print("\t",m)
                #     print("-"*40)
                #     r = rules_funcs[p-1](msgs)
                #     print("previous rule",r)                    
                #     r = rules_funcs[p](msgs)
                #     print("this rule",r)
                #     print("-"*40)

                #print(rs[0])
                

                #assert(getmemos(msgs,p)==f(msgs))
                
                # old algorithm rules return NONE, new algorithm rules return [NONE]
                if rs == None: 
                    facts["STAT_Counter_Miss"]+=1
                    prev = p
                    if False: #Short circuit for skipping rules
                        if "VQFW_" in rules_names[p]:
                            p = len(rules)-2
                            prev = p

                    # if p >= VQFW_RULE_ID and p != BYTE_RULE_ID:
                    #     p = len(rules)-2
                    #     prev = p
                else:

                    new_msgs = chomp(msgs,rs)

                    facts["STAT_Counter_Hit"]+=1
                    if p == len(rules)-1:
                        facts["STAT_Counter_Hit_Byte"]+=1
                    #facts["PE"].append((pats+[p],preH(rs)))



                    # Are they all []'s after applying this rule? 
                    # Winnnnnner Winnnner !!!
                    if rs[0] == [] and len(rs)==len([r for r in rs if r == []]):

                        if metadata != None:
                            byte_id = rules_names.index("BYTE")
                            solutions.append((pats+[(p,metadata)]+[byte_id]*metadata,msg_chunks+[new_msgs]))
                            ticket = pats+[(p,metadata)]+[byte_id]*metadata
                        else:
                            solutions.append((pats+[p],msg_chunks+[new_msgs]))
                            ticket = pats+[p]

                        if dumpfunction != None:
                            print(pats+[p])
                            if not dumpedsols[str(ticket)]:
                                print("Dumpfunction",MAXHYPLEN,dumpfunction(ticket,OFFSET))
                                dumpedsols[str(ticket)]=True
                            else:
                                pass
                        # Blast solution out
                        print("FOUND A SOL",ticket)
                        prev = p

                    else:


                        stack.append((msgs,pats,p,msg_chunks))
                        if metadata != None:
                            byte_id = rules_names.index("BYTE")
                            stack.append((rs,pats+[(p,metadata)]+[byte_id]*metadata,-1,msg_chunks+[new_msgs]))
                        else:
                            stack.append((rs,pats+[p],-1,msg_chunks+[new_msgs]))
                        break
        
        return solutions
    

    CUR_DEPTH = 1
    sol = []
    chunks =[]


    # In the case where we have a SHORT circuit, we are setting the MHL to only grow beyond the OFFSET by SHORTCIRCUIT AMOUNT
    #MAXHYPLEN = MAXHYPLEN+OFFSET
    # if SHORTCIRCUIT != None:
    #     MAXHYPLEN = OFFSET + SHORTCIRCUIT
    # No Short Circuit = run until you his MHL


    while CUR_DEPTH <= MAXHYPLEN and len(sol) < MAXSOLS:
        if False:
            print("logging","CUR_DEPTH",CUR_DEPTH,"MAXHYPLEN",MAXHYPLEN, "LENSOL",len(sol))
        # for s in sol:
        #     print(s)
        # Make sure if we find a solution at some depth, and then
        # search deeper, when we fnd the solution a second time, we don't 
        # add it a second time.
        r = search(msgs,CUR_DEPTH,OFFSET,SHORTCIRCUIT)
        for r1,msg1 in r:
            if str(r1) not in [str(s) for s in sol]:
                sol+=[r1]
                chunks+=[msg1]
        CUR_DEPTH+=1
        if len(sol) >= MAXSOLS:
            break


    #facts["STAT_tm"] = time.time()-facts["STAT_tm"]
    del memos
    del memos_lz
    del memo_f
    del memo_f_cache
    del qty

    sol_set = defaultdict(lambda:None)
    for s in sol:
        sol_set[str(s)] = s

    sol = [sol_set[s] for s in sol_set]
    return (sol,facts,chunks)


# -----------------------------------------------------------------------------------------------------





