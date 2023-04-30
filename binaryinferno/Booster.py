

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


# This file lets us run detectors in parallel

from multiprocessing import Pool, TimeoutError
import time
import os
def ff(v):
	l,f,foo= v
	r = f(foo)
	return (l,f,r)

def booster(fs,foo):
	safe = []
	single = []
	res = []
	for l,f in fs:
		if "rep_par" in l:
			single.append((l,f))
		else:
			safe.append((l,f,foo))

	print("safe")
	for v in safe:
		print("\t",v)



	import concurrent.futures


	# Runs up to 5 detectors at a time.

	with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
	    # Start the load operations and mark each future with its URL
	    future_to_url = {executor.submit(ff, v): v for v in safe}
	    for future in concurrent.futures.as_completed(future_to_url):
	        l,f,foo = future_to_url[future]
	        print("Boosting",l)
	        data = future.result()
	        res.append(data)


	# with Pool(processes=4) as pool:


	# 	res+=pool.map(ff, safe)

	for v in single:
		print("\t",v)
		l,f = v
		r = f(foo)
		res.append((l,f,r))
	return res


# def f(x):
#     return x*x

# if __name__ == '__main__':
#     # start 4 worker processes
#     with Pool(processes=4) as pool:

#         # print "[0, 1, 4,..., 81]"
#         print(pool.map(f, range(10)))

#         # print same numbers in arbitrary order
#         for i in pool.imap_unordered(f, range(10)):
#             print(i)

#         # evaluate "f(20)" asynchronously
#         res = pool.apply_async(f, (20,))      # runs in *only* one process
#         print(res.get(timeout=1))             # prints "400"

#         # evaluate "os.getpid()" asynchronously
#         res = pool.apply_async(os.getpid, ()) # runs in *only* one process
#         print(res.get(timeout=1))             # prints the PID of that process

#         # launching multiple evaluations asynchronously *may* use more processes
#         multiple_results = [pool.apply_async(os.getpid, ()) for i in range(4)]
#         print([res.get(timeout=1) for res in multiple_results])

#         # make a single worker sleep for 10 secs
#         res = pool.apply_async(time.sleep, (10,))
#         try:
#             print(res.get(timeout=1))
#         except TimeoutError:
#             print("We lacked patience and got a multiprocessing.TimeoutError")

#         print("For the moment, the pool remains available for more work")

#     # exiting the 'with'-block has stopped the pool
#     print("Now the pool is closed and no longer available")