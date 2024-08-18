/*
    ------ cgoldie ------
    Release 1, 2024-06-16
    This is public domain
          by  jlxip
    ---------------------

    cgoldie is a standalone C99 implementation for the X448 key exchange
    cryptographic algorithm.

    This implementation is constant in branches and memory accesses, so it's
    constant in time and power consumption. It is safe against all types of
    avoidable side-channel attacks.

    All intermediate values are zeroized. No footprints.

    Every function in cgoldie has an associated test. Regular KAT self-tests
    are implemented and their execution is encouraged. Furthermore, cgoldie is
    carefully written so that it will pass any certifications, including FIPS.

    This is a dual implementation: one is optimized for 32-bit words for older
    and/or embedded systems, and another is optimized for 64-bit systems.

    cgoldie is written in portable C99 and does not use dynamic memory.

    References:
    [1] "Ed448-Goldilocks, a new elliptic curve", Mike Hamburg, Rambus
        Cryptography Research, Ham15, 2015
    [2] RFC 7748: "Elliptic Curves for Security"
    [3] "Analyzing and Comparing Montgomery Multiplication Algorithms",
        C. Kaya Koc, T. Acar, B.S. Kaliski, 1996
    [4] "Compact implementations of Curve Ed448 on low‐end IoT platforms",
        Hwajeong Seo, 2019
    [5] "A High-Performance ECC Processor Over Curve448 Based on a Novel Variant
        of the Karatsuba Formula for Asymmetric Digit Multiplier",
        A. M. Awaludin, et al., 2022
*/

/*
    cgoldie is configurable via preprocessor definitions, which can either
    be at the top of the file or, better yet, in a compiler flag (-D).

    cgoldie has two main implementations. Set CGOLDIE_MODE:
    - To 32 for using the 32-bit sized limbs version. For older or embedded
      systems.
    - To 64 for using the 64-bit sized limbs version. For regular processors
      that support it.

    Choose your level of self-tests setting CGOLDIE_TESTS:
    - 0 for no self-tests. You may want to use this if your memory is
      restricted (embedded systems).
    - 1 for X448 self-tests (default).You may use this for the general case.
      It's enough for passing certifications.
    - 2 for all self-tests. Mainly for debugging.
    Additionally, you can set CGOLDIE_VERBOSE to 1 for enabling the use of
    printf for writing to screen if any tests fail (so you know which one).

    Word addition and full multiplication have several implementations.
    - Set CGOLDIE_DEFAULTSUM for using the plain C (slow) implementation for
      the sum-with-carry algorithm.
    - Set CGOLDIE_DEFAULTMUL for the (extremely slow) plain C multiplication.
    Otherwise, compiler intrinsics will try to be used. If your compiler does
    not support the implemented ones, consider implementing your own instead
    of relying on the defaults.

    Always compile cgoldie with "-O3" for the optimizations to be applied.

    NOTE: if you intend to pass certifications, you should hardcode ONE set of
    configurations in order for cgoldie to be considered a single
    implementation.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;

// A BigInt is composed of word-sized limbs
#ifndef CGOLDIE_MODE
#error Please set CGOLDIE_MODE
#elif CGOLDIE_MODE == 0
#define CGOLDIE_32
#define WORD_BITS 32ul
#define HWORD_BITS 16ul
typedef uint32_t word;
typedef uint16_t hword;
#elif CGOLDIE_MODE == 1
#define CGOLDIE_64
#define WORD_BITS 64ul
#define HWORD_BITS 32ul
typedef uint64_t word;
typedef uint32_t hword;
#else
#error CGOLDIE_MODE must be 0 (32 bits) or 1 (64 bits)
#endif

#define LIMBS(X) (((X) + WORD_BITS - 1) / WORD_BITS)

// Tests
#ifndef CGOLDIE_TESTS
#define CGOLDIE_TESTS 1
#endif

#if CGOLDIE_TESTS == 0
#elif CGOLDIE_TESTS == 1
#elif CGOLDIE_TESTS == 2
#else
#error CGOLDIE_TESTS must be 0 (no tests), 1 (X448) or 2 (all)
#endif

// Verbose?
#ifdef CGOLDIE_VERBOSE
#include <stdio.h>
#define CGOLDIE_TEST_FAIL                                                      \
    printf("\n--- Test failed! ---\nLine: %d\n", __LINE__);                    \
    return 0;
#else
#define CGOLDIE_TEST_FAIL return 0;
#endif

// Helpful macros
#define test(X)                                                                \
    do {                                                                       \
        if (!(X)) {                                                            \
            CGOLDIE_TEST_FAIL                                                  \
        }                                                                      \
    } while (0)
#define fullcomp(A, B, I, N)                                                   \
    do {                                                                       \
        for (size_t i = I; i < LIMBS(N); ++i)                                  \
            test((A) == (B));                                                  \
    } while (0)
#define comp(A, B, I, N) fullcomp((A)[i], (B)[i], I, N)
#define compz(A, I, N) fullcomp((A)[i], 0, I, N)
#define comp448(A, B) comp(A, B, 0, 448)
#define compz448(A) compz(A, 0, 448)

/*
    --- Section 0: compiler intrinsics ---
    Basic functions for the rest of the code.
*/

// --- Certain zeroization ---
// This is a volatile function pointer to memset, it's thus guaranteed to
// execute, and will not be washed away by the optimizer.
void *(*const volatile vmemset)(void *, int, size_t) = memset;
#define zeroize(PTR, SZ) vmemset(PTR, 0, SZ)
#define zerow(PTR) zeroize(PTR, sizeof(word))

// --- Word addition with carry ---
static word __add(word *out, word a, word b) {
#if defined(CGOLDIE_DEFAULTSUM)
    // Default implementation (unoptimized)
    *out = a + b;
    return ((~*out & (a ^ b)) | (a & b)) >> (WORD_BITS - 1);
#elif defined(__has_builtin)
// This covers both GCC and clang
#if __has_builtin(__builtin_add_overflow)
    return __builtin_add_overflow(a, b, out);
#else
#error Builtins, but no __builtin_add_overflow
#endif
#else
#error No __add implementation, consider implementing your own or set CGOLDIE_DEFAULTSUM
#endif
}

#if CGOLDIE_TESTS == 2
static word test__add(void) {
    // 2 + 3 = 5
    word c = 0;
    test(0 == __add(&c, 2, 3));
    test(c == 5);

    // 0x80...00 + 0x80...00 = 0x00...00 + C
    word half = (word)1 << (WORD_BITS - 1);
    test(1 == __add(&c, half, half));
    test(c == 0);

    // 0xFF...FF + 0xFF...FF = 0xFF...FE + C
    word full = ~(word)0;
    test(1 == __add(&c, full, full));
    test(c == full - 1);
    return 1;
}
#endif

// --- Full word multiplication ---
static void __mul(word *restrict hi, word *restrict lo, word a, word b) {
#if defined(CGOLDIE_DEFAULTMUL)
    //  Default implementation (slow): schoolbook multiplication
    word albl = (a & (((word)1 << HWORD_BITS) - 1)) *
                (b & (((word)1 << HWORD_BITS) - 1));
    word ahbl = (a >> HWORD_BITS) * (b & (((word)1 << HWORD_BITS) - 1));
    word albh = (a & (((word)1 << HWORD_BITS) - 1)) * (b >> HWORD_BITS);
    word ahbh = (a >> HWORD_BITS) * (b >> HWORD_BITS);

    *lo = albl;
    *hi = __add(lo, *lo, ahbl << HWORD_BITS);
    *hi += __add(lo, *lo, albh << HWORD_BITS);
    __add(hi, *hi, ahbl >> HWORD_BITS);
    __add(hi, *hi, albh >> HWORD_BITS);
    __add(hi, *hi, ahbh);

    zerow(&albl);
    zerow(&ahbl);
    zerow(&albh);
    zerow(&ahbh);
#elif defined(CGOLDIE_32) && defined(UINT64_MAX)
    // 32-bit version, use uint64_t
    uint64_t aux = (uint64_t)a * (uint64_t)b;
    *lo = aux & 0xFFFFFFFF;
    *hi = aux >> 32;
    zerow(&aux);
#elif defined(CGOLDIE_64) && defined(__SIZEOF_INT128__)
    // 64-bit version, use __int128
    unsigned __int128 aux = (unsigned __int128)a * (unsigned __int128)b;
    *lo = aux & 0xFFFFFFFFFFFFFFFF;
    *hi = aux >> 64;
    zerow(&aux);
#else
#error No __mul implementation, consider implementing your own or set CGOLDIE_DEFAULTMUL
#endif
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const word kat__mul_a = 0xe3e70682;
static const word kat__mul_b = 0xc8a70639;
static const word kat__mul_ch = 0xb2a12e54;
static const word kat__mul_cl = 0xf7657ef2;
#else
static const word kat__mul_a = 0x6baa9455e3e70682;
static const word kat__mul_b = 0xd4713d60c8a70639;
static const word kat__mul_ch = 0x5958e2f2f45884a8;
static const word kat__mul_cl = 0xe11a9e01f7657ef2;
#endif
static word test__mul(void) {
    // 2 * 3 = 6
    word a = 2, b = 3;
    word hi = 0, lo = 0;
    __mul(&hi, &lo, a, b);
    test(hi == 0);
    test(lo == 6);

    // Random values
    __mul(&hi, &lo, kat__mul_a, kat__mul_b);
    test(hi == kat__mul_ch);
    test(lo == kat__mul_cl);

    // 0xFFFF...FFFF * 0xFFFF...FFFF = 0xFFFF...FFFE0000...0001
    a = ~(word)0;
    b = a;
    __mul(&hi, &lo, a, b);
    test(hi == a - 1);
    test(lo == 1);
    return 1;
}
#endif

/*
    --- Section 1: extended integer types ---
    Secure representation of multiprecision unsigned integers.
*/
typedef word u224[LIMBS(224)]; // Half
typedef word u448[LIMBS(448)]; // Full
typedef word u896[LIMBS(896)]; // Double

// --- Zeroization ---
static void zero224(u224 a) { zeroize(a, sizeof(u224)); }
static void zero448(u448 a) { zeroize(a, sizeof(u448)); }
static void zero896(u896 a) { zeroize(a, sizeof(u896)); }

#if CGOLDIE_TESTS == 2
#define UZEROTEST(N)                                                           \
    u##N a;                                                                    \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        a[i] = i + 1;                                                          \
    zero##N(a);                                                                \
    compz(a, 0, N);                                                            \
    return 1;
static word test_zero224(void) { UZEROTEST(224) }
static word test_zero448(void) { UZEROTEST(448) }
static word test_zero896(void) { UZEROTEST(896) }
#endif

// --- Initialization ---
#define UINIT(N)                                                               \
    zero##N(a);                                                                \
    a[0] = x;
static void init224(u224 a, const word x) { UINIT(224) }
static void init448(u448 a, const word x) { UINIT(448) }
#if CGOLDIE_TESTS == 2
// Only used for tests
static void init896(u896 a, const word x) { UINIT(896) }
#endif

#if CGOLDIE_TESTS == 2
#define UINITTEST(N)                                                           \
    u##N a;                                                                    \
    init##N(a, 69);                                                            \
    test(a[0] == 69);                                                          \
    compz(a, 1, N);                                                            \
    return 1;
static word test_init224(void) { UINITTEST(224) }
static word test_init448(void) { UINITTEST(448) }
static word test_init896(void) { UINITTEST(896) }
#endif

// --- Copy ---
static void copy224(u224 a, const u224 b) { memcpy(a, b, sizeof(u224)); }
static void copy448(u448 a, const u448 b) { memcpy(a, b, sizeof(u448)); }
#if CGOLDIE_TESTS == 2
// Only used for tests
static void copy896(u896 a, const u896 b) { memcpy(a, b, sizeof(u896)); }
#endif

#if CGOLDIE_TESTS == 2
#define UCOPYTEST(N)                                                           \
    u##N a, b;                                                                 \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        b[i] = i + 1;                                                          \
    copy##N(a, b);                                                             \
    fullcomp(a[i], i + 1, 0, N);                                               \
    return 1;
static word test_copy224(void) { UCOPYTEST(224) }
static word test_copy448(void) { UCOPYTEST(448) }
static word test_copy896(void) { UCOPYTEST(896) }
#endif

// --- Move ---
// Two loops to avoid ordering memory dependencies
#define UMOVE(N)                                                               \
    copy##N(a, b);                                                             \
    zero##N(b);
// static void move224(u224 a, u224 b) { UMOVE(224) }
static void move448(u448 a, u448 b) { UMOVE(448) }
// static void move896(u896 a, u896 b) { UMOVE(896) }

#if CGOLDIE_TESTS == 2
#define UMOVETEST(N)                                                           \
    u##N a, b;                                                                 \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        b[i] = i + 1;                                                          \
    move##N(a, b);                                                             \
    fullcomp(a[i], i + 1, 0, N);                                               \
    compz(b, 0, N);                                                            \
    return 1;
// static word test_move224(void) { UMOVETEST(224) }
static word test_move448(void) { UMOVETEST(448) }
// static word test_move896(void) { UMOVETEST(896) }
#endif

// --- Conditional swap ---
#define USWAP(N)                                                               \
    word mask = 1 + ~c;                                                        \
    u##N dummy;                                                                \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        dummy[i] = mask & (a[i] ^ b[i]);                                       \
    for (size_t i = 0; i < LIMBS(N); ++i) {                                    \
        a[i] ^= dummy[i];                                                      \
        b[i] ^= dummy[i];                                                      \
    }                                                                          \
    zerow(&mask);                                                              \
    zero##N(dummy);
// static void swap224(u224 a, u224 b, word c) { USWAP(224) }
static void swap448(u448 a, u448 b, word c) { USWAP(448) }
// static void swap896(u896 a, u896 b, word c) { USWAP(896) }

#if CGOLDIE_TESTS == 2
#define USWAPTEST(N)                                                           \
    u##N a, b;                                                                 \
    for (size_t i = 0; i < LIMBS(N); ++i) {                                    \
        a[i] = i + 1;                                                          \
        b[i] = i * 2;                                                          \
    }                                                                          \
    swap##N(a, b, 0);                                                          \
    fullcomp(a[i], i + 1, 0, N);                                               \
    fullcomp(b[i], i * 2, 0, N);                                               \
    swap##N(a, b, 1);                                                          \
    fullcomp(a[i], i * 2, 0, N);                                               \
    fullcomp(b[i], i + 1, 0, N);                                               \
    return 1;
// static word test_swap224(void) { USWAPTEST(224) }
static word test_swap448(void) { USWAPTEST(448) }
// static word test_swap896(void) { USWAPTEST(896) }
#endif

// --- Addition ---
#define UADD(N)                                                                \
    register word carry = 0;                                                   \
    for (size_t i = 0; i < LIMBS(N); ++i) {                                    \
        carry = __add(&a[i], a[i], carry);                                     \
        carry |= __add(&a[i], a[i], b[i]);                                     \
    }                                                                          \
    return carry;
static word add224(u224 a, const u224 b) {
#ifdef CGOLDIE_32
    UADD(224);
#else
    // Special case for 64 bits, since 224/64 = 3,5
    // First three words at the same
    register word carry = 0;
    for (size_t i = 0; i < 3; ++i) {
        carry = __add(&a[i], a[i], carry);
        carry |= __add(&a[i], a[i], b[i]);
    }

    // In the last, only the first 32 bits count
    a[3] &= ((word)1 << 32) - 1; // pre-clean
    __add(&a[3], a[3], carry);
    carry = (a[3] & ((word)1 << 32)) >> 32;
    __add(&a[3], a[3], b[3] & (((word)1 << 32) - 1));
    carry |= (a[3] & ((word)1 << 32)) >> 32;
    a[3] &= ((word)1 << 32) - 1; // post-clean
    return carry;
#endif
}
static word add448(u448 a, const u448 b) { UADD(448) }
static word add896(u896 a, const u896 b) { UADD(896) }

#if CGOLDIE_TESTS == 2
#define UADDTEST(N)                                                            \
    u##N a, b;                                                                 \
    /* 2 + 3 = 5 */                                                            \
    init##N(a, 2);                                                             \
    init##N(b, 3);                                                             \
    test(0 == add##N(a, b));                                                   \
    test(a[0] == 5);                                                           \
    compz(a, 1, N);                                                            \
    /* Edge case: 0xFFFF...FFFF + 1 = 0 + C */                                 \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        a[i] = ~(word)0;                                                       \
    init##N(b, 1);                                                             \
    test(1 == add##N(a, b));                                                   \
    compz(a, 0, N);                                                            \
    /* Edge case: 0xFF...FF + 0xFF...FF = 0xFF...FE + C */                     \
    for (size_t i = 0; i < LIMBS(N); ++i)                                      \
        a[i] = ~(word)0;                                                       \
    copy##N(b, a);                                                             \
    test(1 == add##N(a, b));                                                   \
    test(a[0] == b[0] - 1); /* 0xFF...FE */                                    \
    fullcomp(a[i], b[0], 1, N - 1);                                            \
    return 1;
static word test_add224(void) {
#ifdef CGOLDIE_32
    UADDTEST(224)
#else
    /* Custom tests for 64-bit implementation */
    u224 a, b;
    // 2 + 3 = 5
    init224(a, 2);
    init224(b, 3);
    test(0 == add224(a, b));
    test(a[0] == 5);
    compz(a, 1, 224);
    /* Edge case: 0xFFFF...FFFF + 1 = 0 + C */
    for (size_t i = 0; i < 3; ++i)
        a[i] = ~(word)0;
    a[3] = ((word)1 << 32) - 1;
    init224(b, 1);
    test(1 == add224(a, b));
    compz(a, 0, 224);
    /* Edge case: 0xFF...FF + 0xFF...FF = 0xFF...FE + C */
    for (size_t i = 0; i < 3; ++i)
        a[i] = ~(word)0;
    a[3] = ((word)1 << 32) - 1;
    copy224(b, a);
    test(1 == add224(a, b));
    test(a[0] == b[0] - 1);
    fullcomp(a[i], b[0], 1, 192);
    return 1;
#endif
}
static word test_add448(void) { UADDTEST(448) }
static word test_add896(void) { UADDTEST(896) }
#endif

// --- Partial substraction ---
// Only use for a >= b
static void psub448(u448 a, const u448 b) {
    // Get -b with two's complement
    u448 nb;
    copy448(nb, b);
    for (size_t i = 0; i < LIMBS(448); ++i)
        nb[i] = ~nb[i];
    u448 one;
    init448(one, 1);
    add448(nb, one);

    // a = a + (-b)
    (void)add448(a, nb);
    zero448(nb);
    zero448(one);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const u448 kat_psub448_a = {0xf7c1bd87, 0x7a024204, 0x5ba91faf,
    0x9558867f, 0xe443df78, 0xe87a1613, 0x37ebdcd9, 0x81332876, 0x23a7711a,
    0x48268673, 0x23c6612f, 0xc17c6279, 0x1846d424, 0x9e4d6e3c};
static const u448 kat_psub448_b = {0x3458a748, 0xf77383c1, 0x8d723104,
    0x7a1d5006, 0x71545a13, 0xdd84f39e, 0x85776e9a, 0x42af9fc3, 0x0ff18e02,
    0xce164dba, 0xeb2083e6, 0x8c778ea6, 0xea7e9d49, 0x03983ca8};
static const u448 kat_psub448_c = {0xc369163f, 0x828ebe43, 0xce36eeaa,
    0x1b3b3678, 0x72ef8565, 0x0af52275, 0xb2746e3f, 0x3e8388b2, 0x13b5e318,
    0x7a1038b9, 0x38a5dd48, 0x3504d3d2, 0x2dc836db, 0x9ab53193};
#else
static const u448 kat_psub448_a = {0x7a024204f7c1bd87, 0x9558867f5ba91faf,
    0xe87a1613e443df78, 0x8133287637ebdcd9, 0x4826867323a7711a,
    0xc17c627923c6612f, 0x9e4d6e3c1846d424};
static const u448 kat_psub448_b = {0xf77383c13458a748, 0x7a1d50068d723104,
    0xdd84f39e71545a13, 0x42af9fc385776e9a, 0xce164dba0ff18e02,
    0x8c778ea6eb2083e6, 0x03983ca8ea7e9d49};
static const u448 kat_psub448_c = {0x828ebe43c369163f, 0x1b3b3678ce36eeaa,
    0x0af5227572ef8565, 0x3e8388b2b2746e3f, 0x7a1038b913b5e318,
    0x3504d3d238a5dd48, 0x9ab531932dc836db};
#endif
static word test_psub448(void) {
    u448 c;
    copy448(c, kat_psub448_a);
    psub448(c, kat_psub448_b);
    comp448(c, kat_psub448_c);
    return 1;
}
#endif

// --- Multiplication ---
// Schoolbook multiplication
// If your system is deeply embedded, you probably want Karatsuba instead
static void mul448(u896 out, const u448 a, const u448 b) {
    u896 hi, lo;
    zero896(out);
    for (size_t i = 0; i < LIMBS(448); ++i) {
        zero896(hi);
        zero896(lo);
        for (size_t j = 0; j < LIMBS(448); ++j)
            __mul(&hi[i + j + 1], &lo[i + j], a[i], b[j]);
        add896(out, hi);
        add896(out, lo);
    }
    zero896(hi);
    zero896(lo);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const u448 kat_mul448_1a = {0x17e0aa3c, 0xb83e90ec, 0xd71037d1,
    0x66194cb1, 0xb5d32b16, 0xd3290a4c, 0xc8f8e3d0, 0xab0c1681, 0xa0116be5,
    0x004ae545, 0x9ca5499d, 0x7e5b1e7f, 0xd3fbf47a, 0xde1b372a};
static const u448 kat_mul448_1b = {0x55485822, 0x3e70f16a, 0xbaf3897a,
    0x534097ca, 0xb421eaeb, 0xded733e8, 0x101fbccc, 0x30e9c5cc, 0xeac1c14f,
    0x9148624f, 0x38c1962e, 0x3d15eef7, 0xcda8056c, 0xf7b0b7d2};
static const u896 kat_mul448_1c = {0x333b3bf8, 0x85fdb01e, 0x09087540,
    0x294c84fa, 0x02597268, 0xb38c9096, 0x20622126, 0x0f87feda, 0x33a31345,
    0x4e47f8f8, 0x77d364bb, 0xab610630, 0x5d8de3b8, 0xf9a93617, 0xb903eee8,
    0x8cf6d080, 0x48431a19, 0xbb20ad2c, 0xc176e46a, 0x2a109989, 0xfefe257d,
    0x8fb83a3c, 0xd1f4ea3d, 0x5b1d97f2, 0x48df35e4, 0x34fd65e9, 0x992a4683,
    0xd6e5946c};
static const u448 kat_mul448_2a = {0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
static const u896 kat_mul448_2c = {0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xfffffffe,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff};
#else
static const u448 kat_mul448_1a = {0xb83e90ec17e0aa3c, 0x66194cb1d71037d1,
    0xd3290a4cb5d32b16, 0xab0c1681c8f8e3d0, 0x004ae545a0116be5,
    0x7e5b1e7f9ca5499d, 0xde1b372ad3fbf47a};
static const u448 kat_mul448_1b = {0x3e70f16a55485822, 0x534097cabaf3897a,
    0xded733e8b421eaeb, 0x30e9c5cc101fbccc, 0x9148624feac1c14f,
    0x3d15eef738c1962e, 0xf7b0b7d2cda8056c};
static const u896 kat_mul448_1c = {0x85fdb01e333b3bf8, 0x294c84fa09087540,
    0xb38c909602597268, 0x0f87feda20622126, 0x4e47f8f833a31345,
    0xab61063077d364bb, 0xf9a936175d8de3b8, 0x8cf6d080b903eee8,
    0xbb20ad2c48431a19, 0x2a109989c176e46a, 0x8fb83a3cfefe257d,
    0x5b1d97f2d1f4ea3d, 0x34fd65e948df35e4, 0xd6e5946c992a4683};
static const u448 kat_mul448_2a = {0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff};
static const u896 kat_mul448_2c = {0x0000000000000001, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0xfffffffffffffffe,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
#endif
static word test_mul448(void) {
    u896 c;
    mul448(c, kat_mul448_1a, kat_mul448_1b);
    comp(c, kat_mul448_1c, 0, 896);
    mul448(c, kat_mul448_2a, kat_mul448_2a);
    comp(c, kat_mul448_2c, 0, 896);
    return 1;
}
#endif

/*
    --- Section 2: Galois field ---
    Secure, fast representation of GF(2^448 - 2^224 - 1)
    From here on, p = 2^448 - 2^224 - 1
*/

// goldie = element of Goldilocks (the field)
// The different type is for code clarity
// A goldie is a u448 but *always* less than p
typedef u448 goldie;
#define zerog zero448
#define initg init448
#define copyg copy448
#define moveg move448
#define swapg swap448

// p, in u448
#ifdef CGOLDIE_32
static const u448 p = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
#else
static const u448 p = {0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xfffffffeffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff};
#endif
// p-1, in u448; only used for some tests
#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie pm1 = {0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
#else
static const goldie pm1 = {0xfffffffffffffffe, 0xffffffffffffffff,
    0xffffffffffffffff, 0xfffffffeffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff};
#endif
#endif
// -p, in u448 (2*448 - p)
#ifdef CGOLDIE_32
static const goldie negp = {0x00000001, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};
#else
static const goldie negp = {0x0000000000000001, 0x0000000000000000,
    0x0000000000000000, 0x0000000100000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000};
#endif

// --- Small reduction ---
// u448 -> goldie
static void sred(u448 a) {
    // Consider this a specific case of Barrett reduction
    // Since p < repr < p*2, one substraction is needed at most; goldie has
    // intrinsic modulus. Thus, let b = a - p, then swap a and b if necessary
    u448 b;
    word carry;

    copy448(b, a);
    carry = add448(b, negp);
    swap448(a, b, carry);

    zero448(b);
    zerow(&carry);
}

#if CGOLDIE_TESTS == 2
// ~0 % (2^448 - 2^224 - 1)
#ifdef CGOLDIE_32
static const goldie kat_sred_r = {0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
#else
static const goldie kat_sred_r = {0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000100000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000};
#endif
static word test_sred(void) {
    u448 a;

    // (p-1) % p = p-1
    copy448(a, pm1);
    sred(a);
    comp448(a, pm1);
    // p % p = 0
    copy448(a, p);
    sred(a);
    compz448(a);
    // ~0 % p = KAT#1
    for (size_t i = 0; i < LIMBS(448); ++i)
        a[i] = ~(word)0;
    sred(a);
    comp448(a, kat_sred_r);
    return 1;
}
#endif

// --- Big reduction ---
// u896 -> u448. Source: [4]
static void bred(goldie out, const u896 a) {
    word e[6];
    u224 T;

#ifdef CGOLDIE_32
    // Since u896 = word[112] and u224 = word[28],
    // alignment, strict aliasing, and type punning rules don't apply,
    // and this is safe
    const u224 *A = (const u224 *)a;
    u224 *C = (u224 *)out;
#else
    // 64-bit version is more complex, because 224/64 = 3,5
    u224 A[4], C[2];
    for (size_t i = 0; i < 4; ++i) {
        A[i][3] = 0;
        memcpy(A[i], (char *)a + i * (8 * 3 + 4), 8 * 3 + 4);
    }
#endif

    // Step 1: e0||T <- A[2] + A[3]
    copy224(T, A[2]);
    e[0] = add224(T, A[3]);
    // Step 2: e1||C[0] <- A[0] + e0||T
    copy224(C[0], A[0]);
    e[1] = add224(C[0], T);
    e[1] += e[0];
    // Step 3: e2||C[1] <- A[1] + A[3] + e0||T
    copy224(C[1], A[1]);
    e[2] = add224(C[1], A[3]);
    e[2] += add224(C[1], T);
    e[2] += e[0];
    // Step 4: e3||C[0] <- C[0] + e2
    init224(T, e[2]); // Recycle
    e[3] = add224(C[0], T);
    // Step 5: e4||C[1] <- C[1] + (e1+e2+e3)
    init224(T, e[1] + e[2] + e[3]); // Recycle
    e[4] = add224(C[1], T);
    // Step 6: e5||C[0] <- C[0] + e4
    init224(T, e[4]); // Recycle
    e[5] = add224(C[0], T);
    // Step 7: C[1] <- C[1] + (e4+e5)
    init224(T, e[4] + e[5]); // Recycle
    add224(C[1], T);

#ifdef CGOLDIE_64
    zero448(out);
    for (size_t i = 0; i < 2; ++i)
        memcpy((char *)out + i * (8 * 3 + 4), C[i], 8 * 3 + 4);
    zeroize(A, sizeof(A));
    zeroize(C, sizeof(C));
#endif

    sred(out); // Not sure if this is needed but just in case

    zeroize(e, sizeof(e));
    zero224(T);
    // A = NULL;
    // C = NULL;
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_bred_1r = {0x7bf7651f, 0xe4e96adc, 0xac69274c,
    0x2d4c680a, 0xf8cdbcbc, 0x76c770a2, 0xf645db10, 0xe7fc623e, 0x6483b840,
    0x4cc642f7, 0xc4b27db0, 0xd6d2b66d, 0xb9f30a48, 0xa672846d};
static const goldie kat_bred_2r = {0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
#else
static const goldie kat_bred_1r = {0xe4e96adc7bf7651f, 0x2d4c680aac69274c,
    0x76c770a2f8cdbcbc, 0xe7fc623ef645db10, 0x4cc642f76483b840,
    0xd6d2b66dc4b27db0, 0xa672846db9f30a48};
static const goldie kat_bred_2r = {0x0000000000000001, 0x0000000000000000,
    0x0000000000000000, 0x0000000100000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000};
#endif
static word test_bred(void) {
    goldie r;
    bred(r, kat_mul448_1c);
    comp448(r, kat_bred_1r);
    bred(r, kat_mul448_2c);
    comp448(r, kat_bred_2r);
    return 1;
}
#endif

// --- Addition ---
// Note that 'a' and 'b' MUST be goldie, not u448; that is,
// the MUST be less than p. Otherwise, this will not work
static void add(goldie a, const goldie b) {
    // First add
    word of = add448(a, b);

    // If overflow, substract p
    u448 c;
    copy448(c, a);
    (void)add448(c, negp);
    swap448(a, c, of);

    // Always reduce
    sred(a);

    zerow(&of);
    zero448(c);
}

#if CGOLDIE_TESTS == 2
// ((p-1) + (p-1)) % p
#ifdef CGOLDIE_32
static const goldie kat_add_r = {0xfffffffd, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
#else
static const goldie kat_add_r = {0xfffffffffffffffd, 0xffffffffffffffff,
    0xffffffffffffffff, 0xfffffffeffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff};
#endif
static word test_add(void) {
    // ((p-1) + 1) % p
    goldie a, b;
    copyg(a, pm1);
    initg(b, 1);
    add(a, b);
    compz448(a);
    // ((p-1) + (p-1)) % p
    copyg(a, pm1);
    add(a, pm1);
    comp448(a, kat_add_r);
    return 1;
}
#endif

// --- Negation ---
static void neg(goldie a) {
    // Since a is goldie, p-a >= 0 and na <= p
    // So after reducing (in case a=0), it's a goldie too
    goldie na;
    copy448(na, p);
    psub448(na, a);
    sred(na); // p-0 = p (!!)
    moveg(a, na);
}

#if CGOLDIE_TESTS == 2
static word test_neg(void) {
    // -0 % p = 0
    goldie a;
    zerog(a);
    neg(a);
    compz448(a);
    // -(p-1) % p = 1
    copyg(a, pm1);
    neg(a);
    test(a[0] == 1);
    compz(a, 1, 448);
    return 1;
}
#endif

// --- Substraction ---
static void sub(goldie a, const goldie b) {
    // Compute -b
    goldie nb;
    copyg(nb, b);
    neg(nb);
    // nb += a
    add(a, nb);
    zerog(nb);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_sub_1a = {0x247a8333, 0xcd9d2b7d, 0x8b0163c1,
    0x72ae2244, 0x1759edc3, 0x149818d1, 0xfe43c49e, 0x51ef1922, 0xe005b860,
    0x820865d6, 0xff7b118e, 0xeece328b, 0x7d41e602, 0x1beb3711};
static const goldie kat_sub_1b = {0x4d2b9deb, 0x8d1fd9b7, 0x4a84eb03,
    0xb4e1357d, 0x1ff39849, 0x8c25166a, 0x552f233a, 0xd080e66e, 0xec188efb,
    0x8a5006c1, 0x3405095c, 0xf6be1f72, 0xcca74147, 0x9a6a5f92};
static const goldie kat_sub_1c = {0xd74ee547, 0x407d51c5, 0x407c78be,
    0xbdccecc7, 0xf7665579, 0x88730266, 0xa914a163, 0x816e32b3, 0xf3ed2964,
    0xf7b85f14, 0xcb760831, 0xf8101319, 0xb09aa4ba, 0x8180d77e};
static const goldie kat_sub_1d = {0x28b11ab8, 0xbf82ae3a, 0xbf838741,
    0x42331338, 0x0899aa86, 0x778cfd99, 0x56eb5e9c, 0x7e91cd4b, 0x0c12d69b,
    0x0847a0eb, 0x3489f7ce, 0x07efece6, 0x4f655b45, 0x7e7f2881};
#else
static const goldie kat_sub_1a = {0xcd9d2b7d247a8333, 0x72ae22448b0163c1,
    0x149818d11759edc3, 0x51ef1922fe43c49e, 0x820865d6e005b860,
    0xeece328bff7b118e, 0x1beb37117d41e602};
static const goldie kat_sub_1b = {0x8d1fd9b74d2b9deb, 0xb4e1357d4a84eb03,
    0x8c25166a1ff39849, 0xd080e66e552f233a, 0x8a5006c1ec188efb,
    0xf6be1f723405095c, 0x9a6a5f92cca74147};
static const goldie kat_sub_1c = {0x407d51c5d74ee547, 0xbdccecc7407c78be,
    0x88730266f7665579, 0x816e32b3a914a163, 0xf7b85f14f3ed2964,
    0xf8101319cb760831, 0x8180d77eb09aa4ba};
static const goldie kat_sub_1d = {0xbf82ae3a28b11ab8, 0x42331338bf838741,
    0x778cfd990899aa86, 0x7e91cd4b56eb5e9c, 0x0847a0eb0c12d69b,
    0x07efece63489f7ce, 0x7e7f28814f655b45};
#endif
static word test_sub(void) {
    // a > b
    goldie c;
    copyg(c, kat_sub_1a);
    sub(c, kat_sub_1b);
    comp448(c, kat_sub_1c);
    // a = b
    copyg(c, kat_sub_1a);
    sub(c, kat_sub_1a);
    compz448(c);
    // a < b
    copyg(c, kat_sub_1b);
    sub(c, kat_sub_1a);
    comp448(c, kat_sub_1d);
    return 1;
}
#endif

// --- Multiplication ---
static void mul(goldie a, const goldie b) {
    u896 c;
    mul448(c, a, b);
    bred(a, c);
    zero896(c);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_mul_a = {0x8c1745a7, 0x966e1277, 0x49a3e80e, 0x71eacd05,
    0x1775336d, 0x98a6416d, 0xcc457821, 0x6288e1a5, 0x5129fb7c, 0x935ddd72,
    0x3dfabc08, 0x4a5308cc, 0x2f120554, 0x307bf326};
static const goldie kat_mul_b = {0xd24bace4, 0x2fcd81b5, 0x0870e15c, 0x9cdeb3e6,
    0xfb3675b8, 0xa81ad477, 0x42930b33, 0x79fdef7c, 0x11af923d, 0x16febaa0,
    0xadc0da7a, 0xc1f254b8, 0x215663ab, 0xe07405eb};
static const goldie kat_mul_c = {0x3e588d2d, 0x750c0466, 0x6af96bf0, 0x3ad48fb2,
    0xae2aa132, 0x57d174d6, 0xeddeb3f2, 0x81c7400e, 0xf5f9e093, 0xe26015b6,
    0x86f0a77d, 0x649ab481, 0x18f63c2a, 0x8ea38a5c};
#else
static const goldie kat_mul_a = {0x966e12778c1745a7, 0x71eacd0549a3e80e,
    0x98a6416d1775336d, 0x6288e1a5cc457821, 0x935ddd725129fb7c,
    0x4a5308cc3dfabc08, 0x307bf3262f120554};
static const goldie kat_mul_b = {0x2fcd81b5d24bace4, 0x9cdeb3e60870e15c,
    0xa81ad477fb3675b8, 0x79fdef7c42930b33, 0x16febaa011af923d,
    0xc1f254b8adc0da7a, 0xe07405eb215663ab};
static const goldie kat_mul_c = {0x750c04663e588d2d, 0x3ad48fb26af96bf0,
    0x57d174d6ae2aa132, 0x81c7400eeddeb3f2, 0xe26015b6f5f9e093,
    0x649ab48186f0a77d, 0x8ea38a5c18f63c2a};
#endif
static word test_mul(void) {
    goldie c;
    copyg(c, kat_mul_a);
    mul(c, kat_mul_b);
    comp448(c, kat_mul_c);
    return 1;
}
#endif

// --- Squaring ---
// Fast for squaring once, not for binary exponentiation
static void square(goldie a) {
    // This works since mul only modifies 'a' after computing
    mul(a, a);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_square_a = {0x2648ee38, 0xec62b2c8, 0x09e469e6,
    0xd7ab7928, 0x148b2758, 0xe5eeac76, 0xb306d1a8, 0xec4f217b, 0xd450fe4a,
    0x8a64c1b9, 0xaef9c00b, 0x642bfa42, 0xd67e55fd, 0xb48d73f1};
static const goldie kat_square_s = {0xbd000649, 0x779b1e50, 0x998bc45c,
    0xd4e0cdcb, 0xb005d082, 0x49ccfb58, 0x4b1effd0, 0xcde583f4, 0x9ec2222b,
    0xef832f2b, 0xf4167c8b, 0x5dc38630, 0x5afa8000, 0x5dc1c984};
#else
static const goldie kat_square_a = {0xec62b2c82648ee38, 0xd7ab792809e469e6,
    0xe5eeac76148b2758, 0xec4f217bb306d1a8, 0x8a64c1b9d450fe4a,
    0x642bfa42aef9c00b, 0xb48d73f1d67e55fd};
static const goldie kat_square_s = {0x779b1e50bd000649, 0xd4e0cdcb998bc45c,
    0x49ccfb58b005d082, 0xcde583f44b1effd0, 0xef832f2b9ec2222b,
    0x5dc38630f4167c8b, 0x5dc1c9845afa8000};
#endif
static word test_square(void) {
    goldie s;
    copyg(s, kat_square_a);
    square(s);
    comp448(s, kat_square_s);
    return 1;
}
#endif

// --- Montgomery multiplication ---
// CIOS, or Coarsely Integrated Operand Scanning. Source: [3]
// Used for modular exponentiation
// omega = 2^448 - (2*p % 2^448)
#ifdef CGOLDIE_32
static const u448 omega = {0x00000002, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000002, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};
#else
static const u448 omega = {0x0000000000000002, 0x0000000000000000,
    0x0000000000000000, 0x0000000200000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000};
#endif
#define CIOS_S LIMBS(448)
static void cios(u448 a, const u448 b) {
    word t[CIOS_S + 2] = {0};
    for (size_t i = 0; i < CIOS_S; ++i) {
        // --- Multiply ---
        word C = 0;
        for (size_t j = 0; j < CIOS_S; ++j) {
            // C, t[j] = t[j] + a[j] * b[i] + C
            word S = 0, newC = 0;
            __mul(&newC, &S, a[j], b[i]);
            newC += __add(&S, S, t[j]);
            newC += __add(&S, S, C);
            t[j] = S;
            C = newC;
            zerow(&S);
            zerow(&newC);
        }
        // t[s+1], t[s] = t[s] + C
        t[CIOS_S + 1] = __add(&t[CIOS_S], t[CIOS_S], C);

        // --- Reduce ---
        // For this prime, n'[0] = 1; m = t[0]*n'[0] mod W = t[0]
        word m = t[0];
        // C, _ = t[0] + m * p[0]
        word ignore = 0;
        __mul(&C, &ignore, m, *(word *)p);
        C += __add(&ignore, ignore, t[0]);
        for (size_t j = 1; j < CIOS_S; ++j) {
            // C, t[j-1] = t[j] + m * p[j] + C
            word S = 0, newC = 0;
            __mul(&newC, &S, m, ((word *)p)[j]);
            newC += __add(&S, S, t[j]);
            newC += __add(&S, S, C);
            t[j - 1] = S;
            C = newC;
            zerow(&S);
            zerow(&newC);
        }
        // C, t[s-1] = t[s] + C
        C = __add(&t[CIOS_S - 1], t[CIOS_S], C);
        // t[s] = t[s+1] + C
        t[CIOS_S] = t[CIOS_S + 1] + C;

        zerow(&C);
        zerow(&m);
        zerow(&ignore);
    }

    for (size_t i = 0; i < CIOS_S; ++i)
        a[i] = t[i];

    /*
        t[s] is either 0 or 1
        Since 2^449 < 3*p, at max two substractions are needed

        Number  Case            t[s]    of    ofw    k
        1       a < p           0       0     ?      0
        2       p <= a < 2^L    0       1     ?      1
        3       2^L <= a < 2p   1       ?     0      1
        4       2p <= a         1       ?     1      2
    */
    u448 sub1, distance, sub2;
    copy448(sub1, a);
    word of = add448(sub1, negp);
    copy448(sub2, sub1);
    (void)add448(sub2, negp);
    copy448(distance, a);
    word ofw = add448(distance, omega);

    swap448(a, sub1, t[CIOS_S] | of);  // Cases 1, 2 and 3
    swap448(a, sub2, t[CIOS_S] & ofw); // Case 4

    for (size_t i = 0; i < CIOS_S + 2; ++i)
        t[i] = 0;
    zero448(sub1);
    zero448(distance);
    zero448(sub2);
    zerow(&of);
    zerow(&ofw);
}

#if CGOLDIE_TESTS == 2
static word test_cios(void) {
    // Test as if it were for regular multiplication
    // cios(cios(a, b), R^2) = c
    // R = 2^448 % (2^448 - 2^224 - 1) = negp
    goldie r2;
    copyg(r2, negp);
    square(r2);

    goldie c, d;
    initg(c, 2);
    initg(d, 3);
    cios(c, d);
    cios(c, r2);
    test(c[0] == 6);
    compz(c, 1, 448);

    copyg(c, kat_mul_a);
    cios(c, kat_mul_b);
    cios(c, r2);
    comp448(c, kat_mul_c);
    return 1;
}
#endif

// --- Iterative squaring ---
// Computes a^2^n
static const goldie one = {1};
static void squaren(goldie a, size_t n) {
    // a' = a * R
    mul(a, negp);
    // Note: REDC(a' * a') = REDC(a * R * a * R) = a^2 * R
    while (n--)
        cios(a, a);
    // a = a' * R^-1
    cios(a, one);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_squaren_a = {0x864a7a50, 0x468ff53d, 0x85940927,
    0xcfc6e625, 0x3c49d76f, 0xd977e993, 0x37176e84, 0xe5214606, 0xadf20806,
    0x96fd35d0, 0xd3447490, 0xf323ca74, 0x6b5f5241, 0x9466e472};
static const goldie kat_squaren_b = {0x3b82122a, 0x33ddab86, 0x1551a63f,
    0x819ac2d1, 0xb05adc25, 0xe9b60ef2, 0xb546b2f5, 0x41b04b87, 0x792e192b,
    0xea0b4773, 0x5a3490ed, 0x0249aafe, 0x907b79bc, 0xc7f7a1ac};
#else
static const goldie kat_squaren_a = {0x468ff53d864a7a50, 0xcfc6e62585940927,
    0xd977e9933c49d76f, 0xe521460637176e84, 0x96fd35d0adf20806,
    0xf323ca74d3447490, 0x9466e4726b5f5241};
static const goldie kat_squaren_b = {0x33ddab863b82122a, 0x819ac2d11551a63f,
    0xe9b60ef2b05adc25, 0x41b04b87b546b2f5, 0xea0b4773792e192b,
    0x0249aafe5a3490ed, 0xc7f7a1ac907b79bc};
#endif
static word test_squaren(void) {
    goldie a;
    copyg(a, kat_squaren_a);
    squaren(a, 512);
    comp448(a, kat_squaren_b);
    return 1;
}
#endif

// --- Inversion ---
// Source: [5], since [4] is broken (sigh)
// Either way, it's just a specific case of binary exponentiation
static void inv(goldie z) {
    // Same as the paper, except 'v' is recycled many times, and we save a var
    goldie u, v;
    // 1: u = z^2^1 * z
    copyg(u, z);
    square(u);
    mul(u, z);
    // 2: u = u^2^1 * z
    square(u);
    mul(u, z);
    // 3: u = u^2^3 * u
    copyg(v, u);
    squaren(u, 3);
    mul(u, v);
    // 4: u = u^2^6 * u
    copyg(v, u);
    squaren(u, 6);
    mul(u, v);
    // 5: u = u^2^1 * z
    square(u);
    mul(u, z);
    // 6: u = u^2^13 * u
    copyg(v, u);
    squaren(u, 13);
    mul(u, v);
    // 7: u = u^2^1 * z
    square(u);
    mul(u, z);
    // 8: u = u^2^27 * u
    copyg(v, u);
    squaren(u, 27);
    mul(u, v);
    // 9: u = u^2^1 * z
    square(u);
    mul(u, z);
    // 10: u = u^2^55 * u
    copyg(v, u);
    squaren(u, 55);
    mul(u, v);
    // 11: u = u^2^1 * z
    square(u);
    mul(u, z);
    // 12: v = u^2^111 * u
    copyg(v, u);
    squaren(v, 111);
    mul(v, u);
    // 13: u = v^2^1 * z
    copyg(u, v);
    square(u);
    mul(u, z);
    // 14: u = u^2^223 * v
    squaren(u, 223);
    mul(u, v);
    // 15: u = u^2^2 * z
    squaren(u, 2);
    mul(u, z);
    // z^-1 = u
    moveg(z, u);
    zerog(v);
}

#if CGOLDIE_TESTS == 2
#ifdef CGOLDIE_32
static const goldie kat_inv_a = {0x46743743, 0x73581a81, 0x7e1ea9c5, 0xa905d750,
    0xa425799a, 0xff0ac0f1, 0xb341facd, 0xeabca8d0, 0xfb82860d, 0xcb175a5a,
    0x5b7c709a, 0x15166570, 0x5306f3f5, 0x9cdf5a86};
static const goldie kat_inv_b = {0x8300966d, 0x2c2900e1, 0x145b1de3, 0xf410248a,
    0x670fae2f, 0xf3daf785, 0x3dec0288, 0xe7b6f159, 0xfa1a3962, 0x09bf83ea,
    0xea45cabf, 0x9bc3289a, 0x30a9709d, 0x8477aa8b};
#else
static const goldie kat_inv_a = {0x73581a8146743743, 0xa905d7507e1ea9c5,
    0xff0ac0f1a425799a, 0xeabca8d0b341facd, 0xcb175a5afb82860d,
    0x151665705b7c709a, 0x9cdf5a865306f3f5};
static const goldie kat_inv_b = {0x2c2900e18300966d, 0xf410248a145b1de3,
    0xf3daf785670fae2f, 0xe7b6f1593dec0288, 0x09bf83eafa1a3962,
    0x9bc3289aea45cabf, 0x8477aa8b30a9709d};
#endif
static word test_inv(void) {
    goldie a;
    copyg(a, kat_inv_a);
    inv(a);
    comp448(a, kat_inv_b);
    mul(a, kat_inv_a);
    test(a[0] == 1);
    compz(a, 1, 448);
    return 1;
}
#endif

/*
    --- Section 3: X448 ---
    An extremely fast, constant time, and
    side-channel resistant X448 implementation
    Algorithm from [2]
*/

#define GBYTES (448 / 8)

static void decode_scalar(u8 k[GBYTES]) {
    k[0] &= ~(u8)3; // 0b11
    k[GBYTES - 1] |= 0x80;
}

static const goldie A24 = {39081};
void cgoldie(u8 ss[GBYTES], const u8 k[GBYTES], const u8 u[GBYTES]) {
    // Decode k
    u8 rk[GBYTES];
    for (size_t i = 0; i < GBYTES; ++i)
        rk[i] = k[i];
    decode_scalar(rk);
    // Reduce k, keep as u8[]
    goldie x3;              // Pre-recycling
    memcpy(x3, rk, GBYTES); // Must copy due to alignment and strict aliasing
    sred(x3);
    memcpy(rk, x3, GBYTES); // Must copy due to alignment and strict aliasing

    // Decode and reduce u, keep as goldie
    memcpy(x3, u, GBYTES); // Must copy due to alignment and strict aliasing
    sred(x3);

    // Here we go
    goldie x1, x2, z2, z3;
    copyg(x1, x3); // x_1 = u
    initg(x2, 1);  // x_2 = 1
    zerog(z2);     // z_2 = 0
    // x_3 = u
    initg(z3, 1); // z_3 = 1
    word swap = 0;

    goldie A, AA, B, BB, E, C, D, DA, CB;
    for (size_t i = 0; i < 448; ++i) {
        size_t t = 448 - (i + 1);
        word k_t = 1 & (rk[t / 8] >> (t % 8));
        swap ^= k_t;
        swap448(x2, x3, swap);
        swap448(z2, z3, swap);
        swap = k_t;

        // A = x_2 + z_2
        copyg(A, x2);
        add(A, z2);
        // AA = A^2
        copyg(AA, A);
        square(AA);
        // B = x_2 - z_2
        copyg(B, x2);
        sub(B, z2);
        // BB = B^2
        copyg(BB, B);
        square(BB);
        // E = AA - BB
        copyg(E, AA);
        sub(E, BB);
        // C = x_3 + z_3
        copyg(C, x3);
        add(C, z3);
        // D = x_3 - z_3
        copyg(D, x3);
        sub(D, z3);
        // DA = D * A
        copyg(DA, D);
        mul(DA, A);
        // CB = C * B
        copyg(CB, C);
        mul(CB, B);

        // x_3 = (DA + CB)^2
        copyg(x3, DA);
        add(x3, CB);
        square(x3);
        // z_3 = x_1 * (DA - CB)^2
        copyg(z3, DA);
        sub(z3, CB);
        square(z3);
        mul(z3, x1);
        // x_2 = AA * BB
        copyg(x2, AA);
        mul(x2, BB);
        // z_2 = E * (AA + a24 * E)
        copyg(z2, A24);
        mul(z2, E);
        add(z2, AA);
        mul(z2, E);
    }

    swapg(x2, x3, swap);
    swapg(z2, z3, swap);

    // x_2 * (z_2^(p - 2))
    inv(z2);
    mul(x2, z2);
    memcpy(ss, x2, GBYTES); // Must copy due to alignment and strict aliasing

    zeroize(rk, GBYTES);
    zerog(x1);
    zerog(x2);
    zerog(z2);
    zerog(x3);
    zerog(z3);
    zerow(&swap);
    zerog(A);
    zerog(AA);
    zerog(B);
    zerog(BB);
    zerog(E);
    zerog(C);
    zerog(D);
    zerog(DA);
    zerog(CB);
}

#if CGOLDIE_TESTS != 0
// Test vectors from [2]
static const u8 kat_sm_1k[GBYTES] = {0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e,
    0x88, 0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2, 0x88, 0x82, 0xac,
    0xef, 0x04, 0x51, 0x04, 0xd0, 0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77,
    0x9c, 0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf, 0xf4, 0x49, 0x43,
    0xeb, 0xa3, 0x68, 0xf5, 0x4b, 0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a,
    0xd3};
static const u8 kat_sm_1u[GBYTES] = {0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87,
    0xbf, 0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a, 0xad, 0x88, 0x33,
    0x4c, 0xbd, 0x07, 0x43, 0x7f, 0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0,
    0x31, 0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25, 0x83, 0xfa, 0x54,
    0x29, 0xdb, 0x94, 0xad, 0xa1, 0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0,
    0x86};
static const u8 kat_sm_1o[GBYTES] = {0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc,
    0x66, 0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb, 0xdf, 0x79, 0xb5,
    0x0a, 0x24, 0x12, 0xd7, 0x54, 0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba,
    0xad, 0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77, 0x9d, 0x98, 0x22,
    0x39, 0x61, 0x11, 0x1e, 0x21, 0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b,
    0x6f};
static const u8 kat_sm_2k[GBYTES] = {0x20, 0x3d, 0x49, 0x44, 0x28, 0xb8, 0x39,
    0x93, 0x52, 0x66, 0x5d, 0xdc, 0xa4, 0x2f, 0x9d, 0xe8, 0xfe, 0xf6, 0x00,
    0x90, 0x8e, 0x0d, 0x46, 0x1c, 0xb0, 0x21, 0xf8, 0xc5, 0x38, 0x34, 0x5d,
    0xd7, 0x7c, 0x3e, 0x48, 0x06, 0xe2, 0x5f, 0x46, 0xd3, 0x31, 0x5c, 0x44,
    0xe0, 0xa5, 0xb4, 0x37, 0x12, 0x82, 0xdd, 0x2c, 0x8d, 0x5b, 0xe3, 0x09,
    0x5f};
static const u8 kat_sm_2u[GBYTES] = {0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56,
    0xd3, 0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1, 0xa8, 0xfb, 0x5d,
    0xbb, 0x52, 0xf8, 0xe9, 0xa1, 0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01,
    0x58, 0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5, 0x2f, 0xe2, 0x05,
    0xe2, 0x8a, 0x78, 0xb9, 0x1c, 0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57,
    0xdb};
static const u8 kat_sm_2o[GBYTES] = {0x88, 0x4a, 0x02, 0x57, 0x62, 0x39, 0xff,
    0x7a, 0x2f, 0x2f, 0x63, 0xb2, 0xdb, 0x6a, 0x9f, 0xf3, 0x70, 0x47, 0xac,
    0x13, 0x56, 0x8e, 0x1e, 0x30, 0xfe, 0x63, 0xc4, 0xa7, 0xad, 0x1b, 0x3e,
    0xe3, 0xa5, 0x70, 0x0d, 0xf3, 0x43, 0x21, 0xd6, 0x20, 0x77, 0xe6, 0x36,
    0x33, 0xc5, 0x75, 0xc1, 0xc9, 0x54, 0x51, 0x4e, 0x99, 0xda, 0x7c, 0x17,
    0x9d};
word test_cgoldie(void) {
    u8 out[GBYTES];
    cgoldie(out, kat_sm_1k, kat_sm_1u);
    test(0 == memcmp(out, kat_sm_1o, GBYTES));
    cgoldie(out, kat_sm_2k, kat_sm_2u);
    test(0 == memcmp(out, kat_sm_2o, GBYTES));
    return 1;
}
#endif

/*
    --- Section 4: test interface ---
*/
#if CGOLDIE_TESTS != 0
word cgoldie_test(void) {
#if CGOLDIE_TESTS == 2
    test(test__add());
    test(test__mul());
    test(test_zero224());
    test(test_zero448());
    test(test_zero896());
    test(test_init224());
    test(test_init448());
    test(test_init896());
    test(test_copy224());
    test(test_copy448());
    test(test_copy896());
    // test(test_move224());
    test(test_move448());
    // test(test_move896());
    // test(test_swap224());
    test(test_swap448());
    // test(test_swap896());
    test(test_add224());
    test(test_add448());
    test(test_add896());
    test(test_psub448());
    test(test_mul448());
    test(test_sred());
    test(test_bred());
    test(test_add());
    test(test_neg());
    test(test_sub());
    test(test_mul());
    test(test_square());
    test(test_cios());
    test(test_squaren());
    test(test_inv());
#endif
    test(test_cgoldie());
    return 1;
}
#endif

// jlxip, feb-jun 2024
