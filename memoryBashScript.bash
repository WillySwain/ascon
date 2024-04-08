#!/bin/bash

#Program name from arguments
ascon_reference_implementation=$1
ascon_optimized_implementation=$2

#Create output file
memoryTestFile="memoryTest_$(date +"%F %T")"
touch "$memoryTestFile"

#First write number of lines per implementation 
numLinesRef = $(wc -l < "$ascon_reference_implementation.c")
numLinesOpt = $(wc -l < "$ascon_optimized_implementation.c")
echo "Reference code number of lines: $numLinesRef" >> memoryTestFile
echo "Optimized code number of lines: $numLinesOpt" >> memoryTestFile

#Compile current implementations
gcc -o "$ascon_reference_implementation" "$ascon_reference_implementation.c"

gcc -o "$ascon_optimized_implementation" "$ascon_optimized_implementation.c"

#Write stat size to output file
size_ref=$(stat -c %s "$ascon_reference_implementation")
size_opt=$(stat -c %s "$ascon_optimized_implementation")
echo "Size of Reference program using stat: $size_ref bytes" >> memoryTestFile
echo "Size of Optimized program using stat: $size_opt bytes" >>memoryTestFile

