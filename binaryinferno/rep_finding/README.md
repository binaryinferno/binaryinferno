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


# rep_finder_demo
Repetition Design Pattern  Inference Demonstration


```Usage: python3 rep_infer.py -f datafile

Example: python3 rep_infer.py -f example_data/LV_BYTE_VQVL_3edda2553ef563da_100_.txt

Sample Data in example_data:

BYTE_BYTE_BYTE_BYTE_BYTE_BYTE_BYTE_3f6b45893f6be0e4_100_.txt
BYTE_BYTE_BYTE_BYTE_LV_BYTE_3f33da0d3f070b90_100_.txt
BYTE_BYTE_BYTE_BYTE_VQFW_16_VQVL_3f2f8e213f6ccab1_100_.txt
BYTE_BYTE_LV_3dced64b3efb0163_100_.txt
BYTE_BYTE_LV_3f15431f3f1b0fd0_100_.txt
BYTE_BYTE_TLV_BYTE_BYTE_3f68943d3d02c69e_100_.txt
BYTE_BYTE_VQFW_4_3f5572a53ec33cd7_100_.txt
BYTE_TLV_TLV_3f29c25d3ebacf91_100_.txt
BYTE_VQFW_2_BYTE_3eacede13e466603_100_.txt
LV_BYTE_BYTE_3ebeab9b3ec3bf92_100_.txt
LV_BYTE_VQVL_3edda2553ef563da_100_.txt
NONE_3d84cf993f251144_100_.txt
NONE_3f4252a83f3e3414_100_.txt
NONE_3f78dc2d3ee2f96f_100_.txt
TLV_BYTE_VQFW_4_3f1cb4403e37eeef_100_.txt
TLV_TLV_LV_3f204e8f3e45644d_100_.txt
TLV_VQFW_2_VQFW_2_3ca2ba2d3d3b7906_100_.txt
TLV_VQFW_4_BYTE_3edc07033f637700_100_.txt
VQFW_2_VQVL_TLV_3e6aaa033f19c5fc_100_.txt
VQVL_BYTE_BYTE_BYTE_BYTE_LV_3f2908c53ec5c258_100_.txt
VQVL_BYTE_VQVL_3ecdabcb3f6068bf_100_.txt
VQVL_TLV_LV_3d892d663d7e1e87_100_.txt
VQVL_VQVL_TLV_3ece39913f29b57f_100_.txt
VQVL_VQVL_VQFW_16_3f22a3cd3ed0e836_100_.txt

Example Output:

$python3 rep_infer.py -f example_data/LV_BYTE_VQVL_3edda2553ef563da_100_.txt


████████╗██╗   ██╗███████╗████████╗███████╗
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
    ╚═════╝ ╚═╝     ╚═════╝ ╚═╝   ╚═╝      
   Design Pattern Driven Inference Tool

********************************************************************************

There are 1 total input files to test inference on

********************************************************************************

Summary of values in : example_data/LV_BYTE_VQVL_3edda2553ef563da_100_.txt

Ground Truth: ['LV', 'BYTE', 'VQVL']
----------------------------------------------------------------------------------------------------------------------------------
Byte  :    0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29
----------------------------------------------------------------------------------------------------------------------------------
msg 0 :   48   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36 ...
msg 1 :   47   0  22 113 248 151 237  29 121 168  49  18 130 214 193 229  16  62 130 159  82 168  64 129 247 177 240  95 210 232 ...
msg 2 :   20   0  38 175 112 248 193 133 183  71  31  22  51 141 253 254  91  95  52 139  65 233   0
msg 3 :  154   0  20  28  95 181 183 178 226 157   6  93  82 178 241 137  64 104  29 159 102  19 108 224  66  24  29 223  33  97 ...
msg 4 :    4   0   0   1  72 233   1 108  99 104  97  99 104  97  50  48  45 112 111 108 121  49  51  48  53  64 111 112 101 110 ...
msg 5 :    4   0   0   1  72 233   2 108  99 104  97  99 104  97  50  48  45 112 111 108 121  49  51  48  53  64 111 112 101 110 ...
msg 6 :    4   8   1   3  16 233   8 157  97 101 115  49  50  56  45  99 116 114  44  97 101 115  49  57  50  45  99 116 114  44 ...
msg 7 :   48   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36 ...
msg 8 :    4   0   0   1  72 233   5 157  97 101 115  49  50  56  45  99 116 114  44  97 101 115  49  57  50  45  99 116 114  44 ...
msg 9 :   48   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36 ...

********************************************************************************
File Ground Truth Message Format: ['LV', 'BYTE', 'VQVL']
********************************************************************************

Inferred Format: ['LV', 'BYTE', 'VQVL']
```
