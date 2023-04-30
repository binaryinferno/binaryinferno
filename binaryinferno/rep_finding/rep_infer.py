import argparse
import os
import pickle
import time


#from Rules import rules_names,rules_funcs ,getrules
from Rules import getrules
#from Rules import leadingZerosCheck,getrules
RULEENDIAN = "any"




import multiprocessing
from multiprocessing.dummy import Pool as ThreadPool
import copy


import sys
sys.path.append('../../')
from Sigma import SIGMA,FIELD,INTERVAL
#from GatrSearch import methsupersearch
from GatrSuperSearch2 import supersearch
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

def stream2msgs(xs):
    import re
    xs = re.sub('[ \t]+','',xs,flags=re.M)

    xs = [ x for x in bytes.fromhex(xs)]
    return xs

def sol2intevals(sol,msgs):
    
    rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids,rules_lzf =getrules(RULEENDIAN)
    print("Attepting to convert sol to intervals")
    rids = []
    for s in sol:
        if type(s) == type(()):
            rids.append(s[0])
        else:
            rids.append(s)
    print([rules_names[s] for s in rids])

    # Are we doing BE or LE?
    # if True:
    #     from Rules import rules_be as rules
    #     rules_names = [r[0] for r in rules]
    #     rules_funcs = [r[1] for r in rules]

    # Create an array of intervals the same size as number of messages
    intervals = [[] for i in range(len(msgs))]
    starts = [0]*len(msgs)

    for f_id in sol:
        print(f_id)

        # Star type rules come back as tuples of the rule name and the offset from end.
        if type(f_id)==type(()):
            f_id,offset = f_id

            # if offset == 0 then the are star patterning to the end of the msg
            # Which means we need to consume the entire message 
            if offset == 0:
                f = lambda zs: [[] for xs in zs]
            else:
                f = lambda zs: [xs[-offset:] for xs in zs]
        # Regular rules come back as functions
        else:
            f = rules_funcs[f_id]

        rule_name = rules_names[f_id]
        #print("rule_name",rule_name)
        new_msgs = f(msgs)
        #print("new",len(new_msgs),len(msgs))
        for i in range(len(msgs)):
            diff = len(msgs[i])-len(new_msgs[i])
            start = starts[i]
            stop = starts[i]+diff

            # If the rule isn't a byte rule, for each message, give it a name, a start and a stop
            if rule_name != "BYTE":

                intervals[i].append((rule_name,start,stop))

            #print(i,"start",starts[i],"msgi",msgs[i], "newmsgi",new_msgcat s[i],"diff", diff, "span",starts[i],":",starts[i]+diff)
            starts[i]+=diff
        msgs = new_msgs

    # for i,v in enumerate(intervals):
    #     print("interval",i,v)
    return intervals


# Given a solution (list of rule_ids), I convert it to intervals, and print the pickled version
def dumpsol(sol,msgs,OFFSET=None):
    print("Attempting to dump sol",sol)
    try:
        r = sol2intevals(sol,msgs)
    except:
        print("Failed to dump sol :(")
        print("Probably wasn't valid for some message outside of the short set we use for inference")
        return 
    raw_fields = []
    # How many fields are there in here? 
    # Each row of data should have 
    qty_fields = len(r[0])
    #print(qty_fields)
    for field_index in range(qty_fields):

        # Create a field
        raw_fields.append([])
        for row in r:
            #print(field_index,"\t\t",row[field_index])

            # For the field we just created, add in the interval data (name, start, stop)
            raw_fields[-1].append(row[field_index])

    #intervals = [INTERVAL("F",i,i+4) for x in xs]
    fields = []
    for raw_field in raw_fields:
        intervals = []
        for interval in raw_field:
            intervals.append(INTERVAL("R",interval[1],interval[2]))
        annotation = raw_field[0][0]
        field = FIELD(intervals,annotation=annotation,valuescale=.9)
        fields.append(field)
    s = SIGMA(fields)
    print("@@@",[f.annotation for f in s.fields],"@@@",OFFSET,flush=True)
    print("<<<"+pickle.dumps([s]).hex()+">>>",flush=True)
    #return s

def infer_reps(txtmsgs,offset=0,txtfile=None,qtysols=1,mhl=300,answerfmt=False,shortcircuit=None,filterrules=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("-mhl", "--maxhyplen", type=int,  help="Max Hypothesis Length",      default=mhl)
    parser.add_argument("-mml", "--minmsglen", type=int,  help="Min Message Length",         default=0)
    parser.add_argument("-t",   "--timeout",   type=int,  help="Max time to run in seconds", default=120)
    parser.add_argument("-s",   "--samples",   type=int,  help="Number of Samples",          default=32)
    parser.add_argument("-sol", "--qtysols",   type=int,  help="Number of Solutions",        default=qtysols)
    parser.add_argument("-u",   "--uid",                  help="Unique Identifier",          default=int(time.time()))
    parser.add_argument("-f",   "--file",                 help="single model")
    parser.add_argument("-d",   "--dir",                  help="directory to get models from")
    parser.add_argument("-a",   "--alg",                  help="algorithm", default="supersearch")
    parser.add_argument("-dl",  "--dirlimit",  type=int,  help="limit on number of files to get from directory")
    parser.add_argument("-o",   "--output",   help="filename for output", default="output.txt")
    parser.add_argument("-q",   "--txtfile",                 help="file")
    parser.add_argument("-y",   "--offset", type=int,                 help="byteoffset",default = 0)
    parser.add_argument("-c",   "--shortcircuit", type=int,                 help="shortcircuit",default = shortcircuit)

    args = parser.parse_args([])


    rules,rules_names,rules_funcs,rules_star_pairs,rules_star_ids,rules_lzf =getrules(RULEENDIAN)


    msgs = []
    if txtfile!=None:
        f = open(txtfile)
        txtmsgs = f.read()
        f.close()
    for l in txtmsgs.strip().split("\n"):
        xs = stream2msgs(l)
        msgs.append(xs)


    # hack to force max use of samples
    args.samples = len(msgs)
    cargs = {}
    oargs = vars(args)

    for k in oargs:
        cargs["ARG_"+k] = oargs[k]

    # I am the function that prints the pickles representation of the intervals
    # I capture messages and use a lambda to invoke
    def dumpf(sol,OFFSET=None):
        return dumpsol(sol,msgs,OFFSET)

    print("Calling super search w RE",RULEENDIAN)
    sol,facts,chunked_msgs = supersearch(msgs,cargs,offset,dumpfunction=dumpf,RULEENDIAN=RULEENDIAN,filterrules=filterrules)

    print("Found",len(sol),"sols")
    solstrs = []
    sol = sorted(sol,key=lambda x:len(x))


    # Given a rule, get the name
    def getrulename(r):

        # If it's a star type rule, get the first element as the name
        if type(r) == type(()):
            return r[0]
        else:
            return r

    for s in sol:
        sstr = str([rules_names[getrulename(r)] for r in s])
        solstrs.append(sstr)



    # def sol2intevals(sol,msgs):

    #     # Create an array of intervals the same size as number of messages
    #     intervals = [[] for i in range(len(msgs))]
    #     starts = [0]*len(msgs)
    #     for f_id in sol:
    #         #print(f_id)

    #         # Star type rules come back as tuples of the rule name and the offset from end.
    #         if type(f_id)==type(()):
    #             f_id,offset = f_id
    #             f = lambda zs: [xs[-offset:] for xs in zs]
    #         # Regular rules come back as functions
    #         else:
    #             f = rules_funcs[f_id]

    #         rule_name = rules_names[f_id]
    #         #print("rule_name",rule_name)
    #         new_msgs = f(msgs)
    #         #print("new",len(new_msgs),len(msgs))
    #         for i in range(len(msgs)):
    #             diff = len(msgs[i])-len(new_msgs[i])
    #             start = starts[i]
    #             stop = starts[i]+diff

    #             # If the rule isn't a byte rule, for each message, give it a name, a start and a stop
    #             if rule_name != "BYTE":

    #                 intervals[i].append((rule_name,start,stop))

    #             #print(i,"start",starts[i],"msgi",msgs[i], "newmsgi",new_msgcat s[i],"diff", diff, "span",starts[i],":",starts[i]+diff)
    #             starts[i]+=diff
    #         msgs = new_msgs

    #     # for i,v in enumerate(intervals):
    #     #     print("interval",i,v)
    #     return intervals

    def summarizeSol(xs):
        #print(xs)
        res = []
        byte_count = 0
        while xs != []:
            x,*xs = xs
            if x == "BYTE":
                byte_count+=1
            else:
                # We need to dump the accumulated bytes
                if byte_count != 0:
                    res.append(str(byte_count)+"_BYTES")
                    byte_count = 0
                res.append(x)

        if byte_count != 0:
            res.append(str(byte_count)+"_BYTES")
            byte_count = 0
        return res

    sol = sorted(sol,key=lambda x:-len(x))

    interval_sets = []
    if answerfmt:
        res = []
        for s in sol:
            res.append(str(summarizeSol([rules_names[getrulename(r)] for r in s])))
        return res

    print(len(sol),[summarizeSol([rules_names[getrulename(r)] for r in s]) for s in sol])
    for i,sz in enumerate(sol):
        interval_sets.append(sol2intevals(sz,msgs))
        #print(summarizeSol([rules_names[getrulename(r)] for r in s]))
        #print(solstrs[i])
    return interval_sets


if __name__ == "__main__":
    #def infer_reps(txtmsgs,offset=0,txtfile=None,qtysols=1,mhl=300,answerfmt=False,shortcircuit=None):
    model_txt =  sys.stdin.read()

    print("model_text",model_txt.strip())
    msgs = []
    for l in model_txt.strip().split("\n"):
        xs = stream2msgs(l)
        msgs.append(xs)


    res = infer_reps(model_txt)

if __name__ == '__xmain__':

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
    params = []

    import sys


    if not args.file and not args.dir:
        models = []
        model_txt =  sys.stdin.read()
        msgs = []
        for l in model_txt.strip().split("\n"):
            xs = stream2msgs(l)
            msgs.append(xs)

        print("="*80)
        for m in msgs:
            print(m)
        print("="*80)
        #models = [(None,msgs,{"fname":"stdin"})]

        cargs = {}
        oargs = vars(args)

        for k in oargs:
            cargs["ARG_"+k] = oargs[k]

        for v in cargs:
            print(v,cargs[v])
        sol,facts,chunked_msgs = supersearch(msgs,cargs,RULEENDIAN=RULEENDIAN)
        print("="*80)
        print("-"*80)
        print("Found",len(sol),"sols")
        solstrs = []
        #sol = sorted(sol,key=lambda x:len(x))
        def getrulename(r):
            if type(r) == type(()):
                return r[0]
            else:
                return r

        # for s in sol:
        #     sstr = str([rules_names[getrulename(r)] for r in s])
            
        #     solstrs.append(sstr)


        #fstr([correct,tm,gt,"|".join(solstrs)],facts)
        #print(solstrs)
        # for i,s in enumerate(solstrs):
        #     print('- '*40)
        #     print("Solution",s)
        #     print("")
        #     #print("\t",s)
        #     print("\t\t","\t",s)
        #     cmsgs = chunked_msgs[i]

        #     print([len(field) for field in cmsgs])

        #     def replaceempty(x):
        #         if str(x)=='':
        #             return "<EMPTY>"
        #         else:
        #             return str(x)
        #     for j in range(len(msgs)):
        #         # print(len(msgs))
        #         # print([field[j] for field in cmsgs])
        #         print("\t\tMsg",j,":\t","\t".join([replaceempty(bytes(field[j]).hex()) for field in cmsgs]))
        #     print("")
        #     #for 


        # quit()
        # Input a list rule_ids
        # Output messages chunked by rule applications
        def sol2intevals(sz,msgs):
            intervals = [[] for i in range(len(msgs))]
            starts = [0]*len(msgs)
            for f_id in sz:
                #print(f_id)

                # Star type rules come back as tuples of the rule name and the offset from end.
                if type(f_id)==type(()):
                    f_id,offset = f_id
                    f = lambda zs: [xs[-offset:] for xs in zs]
                else:
                    f = rules_funcs[f_id]

                rule_name = rules_names[f_id]
                #print("rule_name",rule_name)
                new_msgs = f(msgs)
                #print("new",len(new_msgs),len(msgs))
                for i in range(len(msgs)):
                    diff = len(msgs[i])-len(new_msgs[i])
                    start = starts[i]
                    stop = starts[i]+diff

                    if rule_name != "BYTE":
                        intervals[i].append((rule_name,start,stop))

                    #print(i,"start",starts[i],"msgi",msgs[i], "newmsgi",new_msgs[i],"diff", diff, "span",starts[i],":",starts[i]+diff)
                    starts[i]+=diff
                msgs = new_msgs

            # for i,v in enumerate(intervals):
            #     print("interval",i,v)
            return intervals
 
        sol = sorted(sol,key=lambda x:-len(x))

        # for i,s in enumerate(sol):
        #     # for v in sol2intevals(s,msgs):
        #     #     print(v)
        #     print(solstrs[i])

        quit()
        for i,s in enumerate(solstrs):
            print("Inferred Format:",s,sol[i])

            for f_id in sol[i]:

                if type(f_id)==type(()):
                    f_id,offset = f_id
                    f = lambda zs: [xs[-offset:] for xs in zs]
                    #f_id = f_id[0]
                else:
                    f = rules_funcs[f_id]

                
                print("-----")
                print(f)
                new_msgs = f(msgs)
                for i,m in enumerate(msgs):
                    print(m,"-->",new_msgs[i])
                msgs = new_msgs

            #dochunks(sol[i],msgs)

        print("msgs len",len(msgs),"orig msgs",len(msgs))
    #print(sol)
   
        quit()




    #pool = multiprocessing.Pool(processes = 5,maxtasksperchild=1)
    

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
        for m in msgs:
            print(bytes(m).hex())
        #quit()
      
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






