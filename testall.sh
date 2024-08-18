#!/bin/bash -eu

function run {
    echo "  MODE TESTS VERB DEFSUM DEFMUL"
    echo "     $1     $2    $3      $4     $5"

    args="-DCGOLDIE_MODE=$1 "
    if [ $2 != 99 ]; then args+="-DCGOLDIE_TESTS=$2 "; fi
    if [ $3 = 1 ]; then args+="-DCGOLDIE_VERBOSE "; fi
    if [ $4 = 1 ]; then args+="-DCGOLDIE_DEFAULTSUM "; fi
    if [ $5 = 1 ]; then args+="-DCGOLDIE_DEFAULTMUL "; fi

    # NOTE: -pedantic is avoided due to __int128
    # gcc
    gcc -Wall -Wextra -Werror \
        -std=c99 -O3 \
        test_main.c cgoldie.c \
        $args \
        -o cgoldie-test
    echo -n "Binary size: "
    du -h cgoldie-test
    ./cgoldie-test || { echo "Test failed (gcc): $@"; exit 1; }

    # clang
    clang -Wall -Wextra -Werror \
          -std=c99 -O3 \
          test_main.c cgoldie.c \
          $args \
          -o cgoldie-test
    echo -n "Binary size: "
    du -h cgoldie-test
    ./cgoldie-test || { echo "Test failed (clang): $@"; exit 1; }
}

#    MODE TESTS VERB DEFSUM DEFMUL
run     0    99    0      1      1  # Try the default 32 bits, with defaults
run     0     2    1      1      1  # All tests, 32 bits, verbose and defaults
run     0     2    0      1      1  # Same, without verbose (check it works)
run     0     0    0      1      1  # 32 bits, no tests (check it compiles)
run     0     1    0      1      1  # Should work like the first one
run     1     2    1      1      1  # 64 bits, all tests, defaults
run     0     2    1      0      0  # 32 bits, all tests, optimized intrinsics
run     1     2    1      0      0  # 64 bits, all tests, optimized intrinsics

rm ./cgoldie-test
