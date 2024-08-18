cgoldie is a public-domain standalone C99 implementation for the X448 key exchange cryptographic algorithm.

It is written in portable C99 and does not use dynamic memory.

This implementation is constant in time (branches and memory accesses), so it's constant in time and power consumption. It is safe against all types of avoidable side-channel attacks.

cgoldie is carefully written so that it will pass any certifications, including FIPS 140-3:

- All intermediate values are zeroized. No footprints.
- Every function in cgoldie has an associated test. Regular KAT self-tests are implemented and their execution is encouraged.

cgoldie is not the fastest implementation of X448. This is due to not having access to assembly language. However, cgoldie does implement many optimizations to not be far.

This is a dual implementation: one is optimized for 32-bit words for older and/or embedded systems, and another is optimized for 64-bit systems. However, do note that [it's not the fastest out there](speed.jpg).

--------------------------------------------------

For instructions, read [the big comment](#todo) at the top of cgoldie.c

Files in this directory:
- cgoldie.c: cgoldie
- cgoldie.h: optional header file that defines the public functions
- kats.py: Python script that generates the hardcoded test vectors
- test_main.c: entry point of the test program
- testall.sh: bash script that tries all compilation options and runs all tests
