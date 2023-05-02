# BinaryInferno

* BinaryInferno is a tool designed to help automatically reverse engineer the formats of binary messages. 

* BinaryInferno is best described in this paper [BinaryInferno: A Semantic-Driven Approach to Field Inference for Binary Message Formats](https://github.com/binaryinferno/binaryinferno/blob/main/BinaryInferno2023Chandler.pdf).

* Just want to try it on some data?  Quick Start Google Colab Notebook [BinaryInferno.ipynb](https://github.com/binaryinferno/binaryinferno/blob/main/BinaryInferno.ipynb).

* More examples and better documentation will come as time permits. If you'd like to be notified by email [fill out this form](https://forms.gle/xH3rPyn7GvfSm2pL7).

* If you are interested in protocol reverse engineering, consider participating in a related user-study: [https://tsp.cs.tufts.edu/protocol-re/](https://tsp.cs.tufts.edu/protocol-re/)

# Requirements

* Python libraries `sklearn`, `scipy`.
* Command line util `parallel` for serialization pattern search.
 
# Usage 

BinaryInferno takes messages to reverse engineer on stdin. One message per line in Hex format.  Here's the example we use in the paper.

```
01000D60A67AED054150504C45
01001160A67B0504504C554D0450454152
01000E60A67AF9064F52414E4745
```
Basic usage: `cat msgs.txt | python3 blackboard.by`

More complicated usage `cat msgs.txt  | python3 blackboard.py --detectors BE --tslow "2001-02-08 11:41:41" --tshigh "2028-02-08 11:41:41" 1> log.txt 2> errs.txt`


* The detectors flag `BE` means use only BIG ENDIAN detectors
* Use detectors flag `LE` for LITTLE ENDIAN detectors

If you want to just use the entropy boundary search: `--detectors boundBE` or `--detectors boundLE`

Timestamp search is performed when a search span is provided:
* `tslow` is lower bound for timestamps
* `tshigh` is upper bound for timestamps 

You can also limit the search to use a specific detector or combination of detectors:

* `boundBE`
* `boundLE`
* `floatLE`
* `floatBE`
* `seq8LE`
* `seq16LE`
* `seq24LE`
* `seq32LE`
* `seq8BE`
* `seq16BE`
* `seq24BE`
* `seq32BE`
* `length`
* `length2LE`
* `length2BE`
* `length3LE`
* `length3BE`
* `length4LE`
* `length4BE`
* `rep_par_BE` (Serialization Pattern Search using BIG ENDIAN multi-byte fields)
* `rep_par_LE` (Serialization Pattern Search using LITTLE ENDIAN multi-byte fields)
* `lvstar`
* `lvone`

Don't worry if timespan is years too wide, that's totally fine in practice.

`log.txt` contains BinaryInferno's exhaustive output

`errs.txt` contains anything which came out on stderr

We mainly care about the stuff at the very end of log.txt

`cat log.txt | awk '/INFERRED DESCRIPTION/,/SPECEND/'` gives us:

```
INFERRED DESCRIPTION
--------------------------------------------------------------------------------

	?? LLLL | TTTTTTTT RRRRRRRRRRRR
	--
	01 000D | 60A67AED 054150504C45
	01 0011 | 60A67B05 04504C554D0450454152
	01 000E | 60A67AF9 064F52414E4745
	--
	0 ? UNKNOWN TYPE 1 BYTE(S) 3.0
	1 L BE UINT16 LENGTH + 0 = TOTAL MESSAGE LENGTH 6.0
	2 T BE 32BIT SPAN SECONDS 2001-02-08 11:41:41.000000 TO 2028-02-08 11:41:41.000000 1.0 12.0
	3 R 0T_1L_V_BIG* 23.0

QTY SAMPLES
3
HEADER ONLY
?? LLLL | TTTTTTTT RRRRRRRRRRRR
SPECSTART
FieldFixed 1V (Unknown Type 1 Byte(s))
Length 2V_BE (BE uint16 Length + 0 = Total Message Length)
FieldFixed 4V_BE (BE 32BIT SPAN Seconds 2001-02-08 11:41:41.000000 to 2028-02-08 11:41:41.000000 1.0)
FieldRep *Q_0T_1L_1V_BE (0T_1L_V_big*)
SPECEND
```

Please see the paper for details on how to interpret the output. 

# Roadmap

Aspirationally, BinaryInferno will will be refactored with three main goals.

* The integration algorithm refactored as a stand-alone component.
* The serialization pattern search algorithm refactored such that it is easier for a novice to add new patterns.
* A refactored detector interface, allowing arbitrary programs to be called as detectors. 

These efforts will take some time.

