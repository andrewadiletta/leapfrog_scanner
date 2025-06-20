# leapfrog_scanner
This Repo allows users to scan their binary for leapfrog gadgets. To use, reference the poc folder. 

In the poc folder, you will see 3 bash scripts:

1. generate_gadget.sh
2. test_gadget.sh
3. kill_scanners.sh

# Building the pin tool

The pin tool is included in this repo. To build the *.so library files run the following:
```
cd pin-3.28/source/tools/ManualExamples
make
```

# Finding Potential Leapfrog Gadgets

First, you must run the generate_gadget.sh script. Inside the script there is a ```COMMAND``` variable. You can change that to whatever you want, by default it it set to the poc binary. 

```
make -C poc/poc_binary
chmod +x poc/generate_gadgets.sh
./poc/generate_gadgets.sh
```

This will generate 3 files: 

1. itrace.in (this contains a list of source -> jump addresses)
2. itrace.out (this contains the actual process trace)
3. return_addresses.txt (this contains all the PC addresses)

# Testing the Leapfrog Gadgets

Next, you can run the test_gadgets.sh script. This test all the source -> jump addresses in the itrace.in file. 

```
chmod +x ./poc/test_gadgets.sh
./poc/test_gadgets.sh
```

This will generate a few files, including:

1. pin.log
2. simulation_results.out
3. stdout_redirect.txt

Look at the stdout_redirect.txt file and do a search for the output you are looking for if the leapfrog gadet was successful.

Note that this script is hard to kill, so I included a kill_scanners.sh script that will kill all the scanners. 

# Disclaimer:

Andrew Adiletta's affiliation with The MITRE Corporation is provided for identification purposes only, and is not intended to convey or imply MITRE's concurrence with, or support for, the positions, opinions, or viewpoints expressed by the author. All references are public domain.
Approved for Public Release; Distribution Unlimited. Public Release Case Number 25-1091.

©2025 The MITRE Corporation. ALL RIGHTS RESERVED.

