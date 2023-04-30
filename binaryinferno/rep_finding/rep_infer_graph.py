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

import argparse
import os
import pickle
import time
from Rules import rules_names
import multiprocessing
from multiprocessing.dummy import Pool as ThreadPool
import copy

#from GatrSearch import methsupersearch
from GatrSuperSearch import supersearch
#from IsoSingleSearch import supersearch 

#from ArrayGatr import numpysearch 

# Unpickles a file and returns the data
def file2model(fname):
    f = open(fname,'rb')
    data = pickle.load(f)
    gt = data["gt"]
    model = data["model"]
    f.close()
    return gt,model







# Filters messages by min message length and required number of samples
def filterMessage(args,msgs):
    new_msgs = msgs
    if args.minmsglen:
        new_msgs = [m for m in msgs if len(m) >= args.minmsglen]

    if len(new_msgs) >= args.samples:
        return new_msgs[:args.samples]
    else:
        return None

# Given a set of args, pull models from file, or dir as appropriate
def getModels(args):
    models = []

    def processFile(model_fname):
        gt,msgs = file2model(model_fname)
        #print(len(msgs))
        clean_msgs = filterMessage(args,msgs)
        if clean_msgs:
            #print(model_fname)
            if len(gt.split(",")) <= args.maxhyplen:
                facts = {"fname":model_fname}
                models.append((gt,clean_msgs,facts))
            else:
                pass
        else:
            #print("skipping",model_fname)
            pass
    
    if args.dir:
        DIRNAME = args.dir
        FNAMES = os.listdir(DIRNAME)

        if args.dirlimit:
            FNAMES = FNAMES[:args.dirlimit]

        for fname in FNAMES:
                    model_fname = os.path.join(DIRNAME,fname)
                    processFile(model_fname)
    if args.file:
        processFile(args.file)


    return models



# def abortable_worker2(tpl):
#     gt,msgs,args,f,fname = tpl



#     start_time  = time.time()
#     timeout     = args["timeout"]

#     # vargs = vars(args)
#     # nargs = {}
#     # for v in vargs:
#     #     nargs[v] = vargs[v]

#     vargs = copy.deepcopy(args)
#     vargs["fname"] = fname
#     p = ThreadPool(1)
#     wrk = p.apply_async(f, args=[msgs,vargs])
#     p.close()
#     # If we finished in time
#     try:

#         sol,facts = wrk.get(timeout)  # Wait timeout seconds for func to complete.
#         p.terminate()
#         #p.close()
#         #p.join()
#         facts["result"] = "halted" 
#         facts["len_sols"] = len(sol)
#         return (gt,sol,time.time()-start_time,"",-128,facts)

#     # If we ran out of time
#     except multiprocessing.TimeoutError:
#         print("Aborting",""," due to timeout")

#         #return -1
#         p.terminate()
#         #p.close()
#         #p.join()
#         facts = vargs
#         STAT_min_sample_len = min([len(m) for m in msgs])
#         STAT_max_sample_len = max([len(m) for m in msgs])
#         STAT_avg_sample_len = int(sum([len(m) for m in msgs])/len(msgs))
       
#         facts["STAT_min_sample_len"] = STAT_min_sample_len
#         facts["STAT_max_sample_len"] = STAT_max_sample_len
#         facts["STAT_avg_sample_len"] = STAT_avg_sample_len
#         facts["result"] = "timeout"
#         facts["len_sols"] = 0
#         #p.join()
#         return (gt,[],-(time.time()-start_time),"",-128,facts)
#         raise



def fwrap(tpl,q):
    start_time  = time.time()
    gt,msgs,args,f,fname = tpl
    sol,facts = supersearch(msgs,args)
    facts["result"] = "halted"
    q.put( (gt,sol,time.time()-start_time,"",-128,facts))
    return

def task(tpl):
    gt,msgs,args,f,fname = tpl

    TIMEOUT =   args["ARG_timeout"]
    q = multiprocessing.Queue()
    
    #print("tstart")
    process = multiprocessing.Process(target=fwrap,args=(tpl,q,))
    process.daemon = True
    process.start()
    process.join(TIMEOUT)
    
    if process.is_alive():
        #print("Function is hanging!")
        process.terminate()
        # Stuff we do if it didn't work right
        gt,msgs,args,f,fname = tpl
        facts = args
        facts["fname"] = fname


        facts["result"] = "timeout"
        q.put( (gt,[],-TIMEOUT,"",-128,facts))

    #return q.get()
    res = q.get()
    gt,sol,tm,fname,SAMPLES,facts=res
    facts["FACT_gt_hyp_len"] = len(gt.split(","))
    facts["STAT_sols_found"] = len(sol)
    facts["fname"] = fname

    # Lets calculate those stats just in case
    STAT_min_sample_len = min([len(m) for m in msgs])
    STAT_max_sample_len = max([len(m) for m in msgs])
    STAT_avg_sample_len = int(sum([len(m) for m in msgs])/len(msgs))
   
    facts["STAT_min_sample_len"] = STAT_min_sample_len
    facts["STAT_max_sample_len"] = STAT_max_sample_len
    facts["STAT_avg_sample_len"] = STAT_avg_sample_len

    return (gt,sol,tm,fname,SAMPLES,facts)

# def aw(tpl):
#     gt,msgs,args,f,fname = tpl



#     start_time  = time.time()
#     timeout     = args["timeout"]

#     # vargs = vars(args)
#     # nargs = {}
#     # for v in vargs:
#     #     nargs[v] = vargs[v]

#     vargs = copy.deepcopy(args)
#     vargs["fname"] = fname

#     sol,facts = supersearch(msgs,args)
#     facts["len_sol"] = len(sol)
#     facts["result"] = "halted"
#     return (gt,sol,time.time()-start_time,"",-128,facts)


#     # p = ThreadPool(1)
#     # wrk = p.apply_async(f, args=[msgs,vargs])
#     # p.close()
#     # # If we finished in time
#     # try:

#     #     sol,facts = wrk.get(timeout)  # Wait timeout seconds for func to complete.
#     #     p.terminate()
#     #     #p.close()
#     #     #p.join()
         
#     #     return (gt,sol,time.time()-start_time,"",-128,facts)

#     # # If we ran out of time
#     # except multiprocessing.TimeoutError:
#     #     print("Aborting",""," due to timeout")

#     #     #return -1
#     #     p.terminate()
#     #     #p.close()
#     #     #p.join()
#     #     facts = vargs
#     #     STAT_min_sample_len = min([len(m) for m in msgs])
#     #     STAT_max_sample_len = max([len(m) for m in msgs])
#     #     STAT_avg_sample_len = int(sum([len(m) for m in msgs])/len(msgs))
       
#     #     facts["STAT_min_sample_len"] = STAT_min_sample_len
#     #     facts["STAT_max_sample_len"] = STAT_max_sample_len
#     #     facts["STAT_avg_sample_len"] = STAT_avg_sample_len
#     #     facts["result"] = "timeout"
#     #     #p.join()
#     #     return (gt,[],-(time.time()-start_time),"",-128,facts)
#     #     raise

def summaryOfModel(fname):
    hexify = lambda xs: " ".join([hex(x)[2:] for x in xs])
    def prettyify(xs):
        res = []
        for x in xs:
            l = len(str(x))
            res.append((4-l)*" "+str(x))
        return "".join(res)
    gt,msgs = file2model(fname)
    print("")
    print("Summary of values in :",fname)
    print("")
    print("Ground Truth:",gt)
    print("-"*130)

    print("Byte  : "+prettyify([i for i in range(30)]))
    print("-"*130)
    msgs = p[1]
    for i in range(len(msgs[:10])):#sorted(msgs,key=lambda x:-len(x))[:10]:
        m = msgs[:10][i]
        if len(m)>30:
            print("msg",i,":",prettyify(m[:30]),"...")
        else:
            print("msg",i,":",prettyify(m))

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-mhl", "--maxhyplen", type=int,  help="Max Hypothesis Length",      default=10)
    parser.add_argument("-mml", "--minmsglen", type=int,  help="Min Message Length",         default=0)
    parser.add_argument("-t",   "--timeout",   type=int,  help="Max time to run in seconds", default=120)
    parser.add_argument("-s",   "--samples",   type=int,  help="Number of Samples",          default=32)
    parser.add_argument("-sol", "--qtysols",   type=int,  help="Number of Solutions",        default=1)
    parser.add_argument("-u",   "--uid",                  help="Unique Identifier",          default=int(time.time()))
    parser.add_argument("-f",   "--file",                 help="single model")
    parser.add_argument("-d",   "--dir",                  help="directory to get models from")
    parser.add_argument("-a",   "--alg",                  help="algorithm", default="supersearch")
    parser.add_argument("-dl",  "--dirlimit",  type=int,  help="limit on number of files to get from directory")
    parser.add_argument("-o",   "--output",   help="filename for output", default="output.txt")

    args = parser.parse_args()

    #print(args)

    # for v in vars(args):
    #     print(v,vars(args)[v])
    models = getModels(args)


    #pool = multiprocessing.Pool(processes = 5,maxtasksperchild=1)
    params = []

    for m in models:

        # Need to score

        # Need to unify how we calculate internal statistics

        # Need to decide how we are determining timeouts

        # Should unify structure such that regardless of which approach I use (msgs or jumps w arrays)
        # I use the same organization and same branches of execution. 

        #print("="*80)
        gt,msgs,facts = m
        algs = {}
        algs["supersearch"] = supersearch
        #algs["methsupersearch"] = methsupersearch
        #algs["numpysearch"] = numpysearch
        alg = algs[args.alg]
        cargs = {}
        oargs = vars(args)

        for k in oargs:
            cargs["ARG_"+k] = oargs[k]

        params.append((gt,msgs,cargs,alg,facts["fname"]))
      
        #params.append((gt,msgs,vars(args),alg,facts["fname"]))
        
        # sols,fcts = supersearch(msgs,args.samples)
        # print(facts["fname"])
        # for s in sols:
        #     print(gt,[rules_names[r] for r in s])
        # print(fcts)

    banner = """████████╗██╗   ██╗███████╗████████╗███████╗
╚══██╔══╝██║   ██║██╔════╝╚══██╔══╝██╔════╝
   ██║   ██║   ██║█████╗     ██║   ███████╗
   ██║   ██║   ██║██╔══╝     ██║   ╚════██║
   ██║   ╚██████╔╝██║        ██║   ███████║
   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   ╚══════╝
                                           
    ██████╗ ██████╗ ██████╗ ██╗████████╗   
    ██╔══██╗██╔══██╗██╔══██╗██║╚══██╔══╝   
    ██║  ██║██████╔╝██║  ██║██║   ██║      
    ██║  ██║██╔═══╝ ██║  ██║██║   ██║      
    ██████╔╝██║     ██████╔╝██║   ██║      
    ╚═════╝ ╚═╝     ╚═════╝ ╚═╝   ╚═╝      """
    print("")
    print("")
    print(banner)
    print("   Design Pattern Driven Inference Tool")
    print("")
    print("*"*80)
    print("")

    print("There are",len(params),"total input files to test inference on")
    print("")
    results = []
    #results = pool.map(aw, params)
    for p in params:


        res = task(p)
        results.append(res) 

        # form of functions f(msgs,args)

    #pool.close()
    #pool.join()
    #print("all done")
    time.sleep(1)
    #print('len results',len(results))


    def calcFieldNames(results):
        fnames = set()
        for res in results:
            gt,sol,tm,fname,SAMPLES,facts = res
            fnames = fnames.union([name for name in facts])

        fnames = fnames.difference(["PE"])
        return sorted(list(fnames))

    def getfact(f,facts):
        if f in facts:
            return facts[f]
        else:
            return None


    #outputf = open(args.output,"w")

    fnames = calcFieldNames(results)

    def fstr(xs,facts):
        outputf.write( "\t".join([str(x) for x in xs]+[str(getfact(f,facts)) for f in fnames]) +"\n")
    def fstr(xs,facts):
        print( "\t".join(["data"]+[str(x) for x in xs]+[str(getfact(f,facts)) for f in fnames]) )
    #outputf.write("\t".join(["outcome","time","gt","sol"]+[str(f) for f in fnames])+"\n")
    #print("\t".join(["tag","outcome","time","gt","sol"]+[str(f) for f in fnames]))



    for res in results:

        gt,sol,tm,fname,SAMPLES,facts = res

        # Print header
        #print("\t".join(["tag","outcome","time","gt","sol"]+[str(f) for f in fnames]))
        print("*"*80)
        
        if getfact("ARG_file",facts):
            summaryOfModel(facts["ARG_file"])
       
        print("")
        print("*"*80)
        print("File Ground Truth Message Format:",gt)
        print("*"*80)
        print("")
        if tm > 0:
            correct = False
            # If we didn't time out and we produced no solution... call that "NONE"
            if "NONE" in gt and len(sol)==0:
                #fstr([True,tm,gt,str(["NONE"])],facts)
                print("Inferred Format:","['NONE'] No Repetition / Could not be determined")

            else:
                solstrs = []
                for s in sol:
                    sstr = str([rules_names[r] for r in s])
                    correct = correct or (gt == sstr)
                    solstrs.append(sstr)
                #fstr([correct,tm,gt,"|".join(solstrs)],facts)

                for s in solstrs:
                    print("Inferred Format:",s)
        else:
            print("Search timed out")
        print("")
            #fstr(["timeout",tm,gt,"Timeout"],facts)
        #print("factdum",str(facts))
        #print([(f,facts[f]) for f in facts if f != "PE"])
        # for f in sorted(facts["PE"],key=lambda x:((len(x[0])*100)+x[1])):
        #     pats,h = f
        #     sstr = str([rules_names[r] for r in pats])
        #     print(gt,len(pats),sstr[:-1] in gt,h,sstr)
        # for s in sol:
        #     print(gt,[rules_names[r] for r in s],tm)
        #doscore(sol,gt,tm,fname,SAMPLES,facts)


    #outputf.close()
#    import os

#    for fname in os.listdir(DIRNAME):
#                 model_fname = os.path.join(DIRNAME,fname)
#                 fnames.append(model_fname)




#           import pickle






