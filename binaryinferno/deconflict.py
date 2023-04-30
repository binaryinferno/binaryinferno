

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





from Sigma import FIELD,INTERVAL,SIGMA

def deconflict(sigmas):

    start = FIELD([INTERVAL("!",-1000,-1000) for i in range(len(sigmas[0].fields[0].intervals))])

    end = FIELD([INTERVAL("!",1000,1000) for i in range(len(sigmas[0].fields[0].intervals))])

    qty_intervals = len(sigmas[0].fields[0].intervals)

    #print("")
    goods = []
    bads = []

    #good = FIELD([INTERVAL("!",-100,-100) for i in range(len(sigmas[0].fields[0].intervals))])
    #sigmas += [SIGMA([good])]
    
    #indices of all sigmas
    alls = set([i for i in range(len(sigmas))])

    for i,s1 in enumerate(sigmas):
        for j,s2 in enumerate(sigmas): 
            if i != j and i < j:
                #print(i,j,s1,s2,s1 & s2)
                if not s1 & s2:
                    bads.append(i)
                    bads.append(j)

    # print("bads",set(bads))
    # print("goods",alls-set(bads))

    bad_indexes = list(set(bads))
    good_indexes = list(alls-set(bads))

    #print(bad_indexes,good_indexes)
    #quit()


    safe_fs = [sigmas[i] for i in good_indexes]

    # These fields conflict and need to be deconflicted
    bad_fs = []
    for s in [sigmas[i] for i in bad_indexes]:
        bad_fs+=s.fields


    # These fields have no conflicts and can be added to every deconflicted sigma
    good_fs = []
    for s in [sigmas[i] for i in good_indexes]:
        good_fs+=s.fields

    if bad_fs == []:
        return SIGMA(good_fs)
    # for f in fs:
    #     print(f,f.width,f.id)
    #     for g in [x for x in fs if x >= f]:
    #         print("\t",g.id)


    # #fs = fs[::-1]
    # print(fs)
    # fs = fs[::2]
    # import random
    # random.shuffle(fs)
    # fs = fs[:6]

    # #random.shuffle(fs)
    # print("fs",fs)
    
    # sfs = sorted(fs) #,reverse=True)

    # print("sfs", sfs)

    # #print(sorted(sfs))

    

    from collections import defaultdict

    dd = defaultdict(lambda:[])
    start = FIELD([INTERVAL("!",-1000,-1000) for i in range(qty_intervals)])
    end = FIELD([INTERVAL("!",1000,1000) for i in range(qty_intervals)])
    
    dd[start.id] = bad_fs + [end]
    for f in bad_fs:
        children = [x for x in bad_fs if x >= f and x != f]
        dd[f.id] = children + [end]  


    def dfs_paths(start, goal, good_fs):
        stack = [(start, [start])]
        visited = set()
        paths= []
        while stack:
            #print(len(stack))
            (vertex, path) = stack.pop()
            #if vertex.lbl not in visited:
            if True:
                if vertex == goal:
                    #return path
                    #print("goal",path,vertex)
                    paths.append(path[::])
                    #path.pop()
                    path.pop()
                else:    
                    visited.add(vertex.id)
                    for neighbor in dd[vertex.id]:
                        stack.append((neighbor, path + [neighbor]))
        # return paths
        sorted_paths = []
        for px in paths:
            p = px[1:-1]
            if p != []:
                sorted_paths.append((sum([x.value for x in p]),SIGMA(p)))
        sorted_paths = sorted(sorted_paths,key=lambda x:x[0],reverse=True)
        #Patch in the good fields which didn't have conflicts
        return [(v,SIGMA(s.fields+good_fs)) for v,s in sorted_paths]
        

    sp = dfs_paths(start,end,good_fs)
    #print(sp)
    if False:
        if len(sp)> 1:
            print("\tConflicts detected: Top 3 options")
            for s in sp[:10]:
                print("\t",s)
    return sp[0][1]