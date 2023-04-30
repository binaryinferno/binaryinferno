

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

# This file wraps up all the parallelization for pattern search
cat - > tmp_par.txt
mml=$1
endianess=$2

# Whats the min message length,
# Use that to determine the max hypothesis length
mml=`cat tmp_par.txt | python3 Stats.py | tail -1`
#echo "MML $mml"
#mml=1000
#result=`python3 gen_sequence.py 0 "$mml" 50 | parallel --halt now,success=1 " cat tmp_par.txt | timeout 10s python3 rep_parallel.py --offset {} -e $endianess"` #--shortcircuit 50"`

step=1

result=`python3 gen_sequence.py 0 "$mml" "$step" | parallel --jobs 30 --joblog joblog.txt "cat tmp_par.txt | python3 trimbytes.py {} | timeout 120s python3 rep_parallel.py --push {} --offset 0 --shortcircuit 1 -e $endianess " > log.txt` #--shortcircuit 50"`

#`echo "MML $mml" >> log.txt`
cat log.txt



