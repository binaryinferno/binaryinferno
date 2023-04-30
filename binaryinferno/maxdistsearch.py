


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

# Find the longest path across the graph encoding of inferred fields

from collections import defaultdict
from Sigma import FIELD,INTERVAL,SIGMA # Use to build our resulting sigma

# Given a graph... topologically sort it to find the order
def toposort(graph):
    """http://code.activestate.com/recipes/578272-topological-sort/
    
    Dependencies are expressed as a dictionary whose keys are items
and whose values are a set of dependent items. Output is a list of
sets in topological order. The first set consists of items with no
dependences, each subsequent set consists of items that depend upon
items in the preceeding sets.
>>> print '\\n'.join(repr(sorted(x)) for x in toposort2({
...     2: set([11]),
...     9: set([11,8]),
...     10: set([11,3]),
...     11: set([7,5]),
...     8: set([7,3]),
...     }) )
[3, 5, 7]
[8, 11]
[2, 9, 10]
"""
    from functools import reduce
    data = defaultdict(set)
    for x, y in graph.items():
        for z in y:
            data[z[0]].add(x)

    # Ignore self dependencies.
    for k, v in data.items():
        v.discard(k)
    # Find all items that don't depend on anything.
    extra_items_in_deps = reduce(set.union, data.values()) - set(data.keys())
    # Add empty dependences where needed
    data.update({item:set() for item in extra_items_in_deps})
    while True:
        ordered = set(item for item, dep in data.items() if not dep)
        if not ordered:
            break
        yield ordered
        data = {item: (dep - ordered)
                for item, dep in data.items()
                    if item not in ordered}
    assert not data, "Cyclic dependencies exist among these items:\n%s" % '\n'.join(repr(x) for x in data.items())


# given a graph which is a DAG, and a labelled start and end node
# find the longest path from start to end. 
def longestpathDAG(graph, startnode, endnode):
    """http://www.geeksforgeeks.org/find-longest-path-directed-acyclic-graph/"""
    ### TOPOLOGICALLY SORT THE VERTICES
    order = []
    for part in toposort(graph):
        order.extend(list(part))
    # order.reverse()

    ### INITIALIZE DISTANCE MATRIX
    LOWDIST=-99999999999999999
    dist = dict((x, LOWDIST) for x in graph.keys())
    dist[startnode] = 0

    ### MAIN PART
    comesfrom = dict()
    for node in order: # u
        for nbr, nbrdist in graph[node]: # v
            if dist[nbr] < dist[node] + nbrdist:
                dist[nbr] = dist[node] + nbrdist
                comesfrom[nbr] = node

    ### BACKTRACKING FOR MAXPATH
    maxpath = [endnode]
    while maxpath[-1] != startnode:
        maxpath.append(comesfrom[maxpath[-1]])
    maxpath.reverse()

    return dist[endnode], maxpath


# exhaustive enumeration of paths to validate that we
# have in fact found the maxpath 
def exhaustive(graph, startnode, endnode):
    maxdist = -1
    stack = [([startnode], 0)]
    while stack:
        cpath, cdist = stack.pop()
        cnode = cpath[-1]
        if cnode == endnode:
            if cdist > maxdist:
                maxdist = cdist
                maxpath = cpath
            continue
        for nbr, nbrdist in graph[cnode]:
            stack.append( (cpath+[nbr], nbrdist+cdist) )

    return maxdist, maxpath



# Given a sigma with fields, find the greatest number of intervals any of those fields contain
def sigma2intervalqty(sigma):
    res = [0]
    for f in sigma.fields:
        res.append(len(f.intervals))
    return max(res)


def fdeconflict(sigmas):

    # How many messages did we originally have... we can get these out of the sigmas by looking at the fields
    #qty_intervals = len(sigmas[0].fields[0].intervals)
    qty_intervals= max([sigma2intervalqty(s) for s in sigmas])





    from collections import defaultdict

    # We need to be able to lookup a field instance from a uid.
    # key: field.id
    uid2field = defaultdict(lambda:None)

    # We need to store all the fields which come after a key(field)
    # key: field.id
    children_dd    = defaultdict(lambda:[])

    # Our source node
    start = FIELD([INTERVAL("!",-10000,-10000) for i in range(qty_intervals)])
    # Our sink node
    end   = FIELD([INTERVAL("!",10000,10000) for i in range(qty_intervals)])

    # print("start",start.id)
    # print("end",end.id)
    #dd[start.id] = bad_fs + [end]
    # Create our fields which are nodes
    # We will think of sigmas as nodes
    # Abstraction: 
    bad_fs = []
    for s in sigmas:
        bad_fs+=s.fields

    # Calculate the children (things which come after fields)
    bad_fs+=[start,end]
    for f in bad_fs:#   +[start,end]:
        uid2field[f.id]  = f

        # everything where f preceeds x

        children = [x for x in bad_fs if x >= f and x != f]

        #print("considering f",f)
        #print("\tconsidering children",children)


        # # filter for things which have ragged edges
        if not f.stopallsame():
            for c in children:
               #print("\t",c,c.startallsame() , c.id != end.id)
               pass
            children = [c for c in children if (not c.startallsame() or c.id == end.id)]
            #print("\tf is not stopallsame")
            #print("\tnew children",children)

        children_dd[f.id] = children #[end]  
        #print("")

    # Now we build our graph. 
    graph = {}
    #print(uid2field)

    # For the set of children associated with a field_id (k)
    for fid in children_dd:
        #print(k)
        f = uid2field[fid] #get the actual field back

        # print(k,f,f.value,"-->",dd[k])
        # print(k,[(c.id,f.value) for c in dd[k]])

        # Add an edge for each child with value f.value
        graph[fid] = [(c.id,f.value) for c in children_dd[fid]]


    startnode = start.id
    endnode = end.id

    # maxdist, maxpath = exhaustive(graph, startnode, endnode)
    # print("Maxdist is %d, maxpath is %s" % (maxdist, [uid2field[m] for m in maxpath]))

    maxdist, maxpath = longestpathDAG(graph, startnode, endnode)

    debug = False
    if debug:
        
        print("Maxdist is %d, maxpath is %s" % (maxdist, [uid2field[m] for m in maxpath]))
    return SIGMA([uid2field[m] for m in maxpath if m != startnode and m != endnode])



def sdeconflict(sigmas):

    # How many messages did we originally have... we can get these out of the sigmas by looking at the fields
    #qty_intervals = len(sigmas[0].fields[0].intervals)
    qty_intervals= max([sigma2intervalqty(s) for s in sigmas])


    def s_first(sigma):
        return sigma.fields[0]
    def s_last(sigma):
        return sigma.fields[-1]



    from collections import defaultdict

    # We need to be able to lookup a sigma instance from a uid.
    # key: sigma.id
    uid2sigma = defaultdict(lambda:None)

    # We need to store all the sigmas which come after a key(sigma)
    # key: sigma.id
    children_dd    = defaultdict(lambda:[])

    # Our source node
    start = SIGMA([FIELD([INTERVAL("!",-10000,-10000) for i in range(qty_intervals)])])
    # Our sink node
    end   = SIGMA([FIELD([INTERVAL("!",10000,10000) for i in range(qty_intervals)])])

    # print("start",start.id)
    # print("end",end.id)
    #dd[start.id] = bad_fs + [end]
    # Create our fields which are nodes
    # We will think of sigmas as nodes
    # Abstraction: 
    bad_s = []
    for s in sigmas:
        if s != SIGMA([]):
            bad_s+=[s]

    # Calculate the children (things which come after fields)
    bad_s+=[start,end]
    for s1 in bad_s:#   +[start,end]:
        uid2sigma[s1.id]  = s1

   
        # Model: SIGMA_S1 ... SIGMA S2 We force the id comparison because that's not built into SIGMA __eq__
        children = [s2 for s2 in bad_s if s2 >= s1 and s2 != s1 and s1.id != s2.id]

        # print("considering s1",s1)
        # for c in children:
        #     print("\tconsidering child",c)


        # # filter for things which have ragged edges
        if not s_last(s1).stopallsame():
            for c in children:
            
               pass
            children = [c for c in children if (not s_first(c).startallsame() or c.id == end.id)]


        children_dd[s1.id] = children #[end]  
        #print("")

    # Now we build our graph. 
    graph = {}

    #print("Building Graph")
    # For the set of children associated with a field_id (k)
    for sid in children_dd:
        #print(k)
        s = uid2sigma[sid] #get the actual field back

        # print("Adding",str(sid),s,len(children_dd[sid]),s.value)
        # for c in children_dd[sid]:
        #     print("\t-->",c)

        # Add an edge for each child with value f.value
        graph[sid] = [(c.id,s.value) for c in children_dd[sid]]


    startnode = start.id
    endnode = end.id

    # maxdist, maxpath = exhaustive(graph, startnode, endnode)
    # print("Maxdist is %d, maxpath is %s" % (maxdist, [uid2field[m] for m in maxpath]))

    maxdist, maxpath = longestpathDAG(graph, startnode, endnode)

    debug = False
    if debug:
        
        print("Maxdist is %d, maxpath is %s" % (maxdist, [uid2sigma[m] for m in maxpath]))
    max_fields = []
    for m in maxpath:
        if m != startnode and m != endnode:
            s =uid2sigma[m] 
            max_fields+=s.fields

    return SIGMA(max_fields)


deconflict = sdeconflict

if __name__ == "__main__":

    graph = {0:[(1, 935.5), (2, 147297.5)], 1:[(3, 1e-10), (4, 945.8)],
             2:[(3, 1e-10),(4, 945.8)], 3:[(5, 3656)], 4:[(6, 7669.5), (7, 18500.5)],
             5:[(6, 7669.5), (7, 18500.5)], 6:[(8, 100)], 7:[(8, 100)], 8:[]}
    startnode, endnode = 0, 8

    maxdist, maxpath = exhaustive(graph, startnode, endnode)
    print("Maxdist is %d, maxpath is %s" % (maxdist, maxpath))

    maxdist, maxpath = longestpathDAG(graph, startnode, endnode)
    print("Maxdist is %d, maxpath is %s" % (maxdist, maxpath))

    # Example at http://www.geeksforgeeks.org/find-longest-path-directed-acyclic-graph/
    graph = {"0":[("1", 5), ("2", 3)], "1":[("3", 6), ("2", 2)],
             "2":[("4", 4), ("5", 2), ("3", 7)], "3":[("5", 1), ("4", -1)],
             "4":[("5", -2)], "5":[]}
    startnode, endnode = "0", "5"

    maxdist, maxpath = exhaustive(graph, startnode, endnode)
    print("Maxdist is %d, maxpath is %s" % (maxdist, maxpath))

    maxdist, maxpath = longestpathDAG(graph, startnode, endnode)
    print("Maxdist is %d, maxpath is %s" % (maxdist, maxpath))




    sigmas = [SIGMA([FIELD([INTERVAL("|",4,4)]),FIELD([INTERVAL("|",9,9)])]),SIGMA([FIELD([INTERVAL("|",6,6)])]),SIGMA([FIELD([INTERVAL("I",4,6)])]),SIGMA([FIELD([INTERVAL("I",4,8)])]),SIGMA([FIELD([INTERVAL("F",8,12)])])]
    for s in sigmas:
        print(s)
    print("FIELDdeconflict----")
    s = fdeconflict(sigmas)
    print(s)

    print("")    

    sigmas = [SIGMA([FIELD([INTERVAL("|",4,4)]),FIELD([INTERVAL("|",9,9)])]),SIGMA([FIELD([INTERVAL("|",6,6)])]),SIGMA([FIELD([INTERVAL("I",4,6)])]),SIGMA([FIELD([INTERVAL("I",4,8)])]),SIGMA([FIELD([INTERVAL("F",8,12)])])]
    for s in sigmas:
        print(s)
    print("SIGMAdeconflict----")
    s = sdeconflict(sigmas)
    print(s)

    

    # s0 =SIGMA([FIELD([INTERVAL("|",4,4)])])
    # s1= SIGMA([FIELD([INTERVAL("|",6,6)])])
    # s2= SIGMA([FIELD([INTERVAL("I",4,6)])])
    # s2b= SIGMA([FIELD([INTERVAL("I",4,6)])])
    # s3= SIGMA([FIELD([INTERVAL("I",4,8)])])
    # s4= SIGMA([FIELD([INTERVAL("F",8,12)])])

    # print("s1 >= s3",s1.fields[0] >= s3.fields[0])
    # print("s3 >= s1",s3.fields[0] >= s1.fields[0])
    # print("s4 >= s3",s4.fields[0] >= s3.fields[0])
    # print("s4 >= s0",s4.fields[0] >= s0.fields[0])
    # print("s0 >= s4",s0.fields[0] >= s4.fields[0])
    # print("s4 >= s3",s4 >= s3)
    # print("s2b >= s2",s2b >= s2)
