# cgoldie: A C Implementation of the X448 Key Exchange Algorithm

**cgoldie** is a lightweight, portable, and secure implementation of the X448 key exchange cryptographic algorithm, designed to be highly performant and suitable for certification.

## Features

- **Portability**: Written in portable **C99**, without dynamic memory allocation.
- **Security**: Uses only constant-time operations, making it resistant to all avoidable side-channel attacks.
- **Performance**: Can achieve over **700 key agreements per second** on a laptop CPU.
- **Certifications**: Designed to pass cryptographic certifications by implementing self-tests and zeroizing all intermediate values.
- **Self-tests**: Provides embedded test vectors to ensure correct execution of operations.

## Requirements

- **Randomness**: You must provide your own secure random numbers. Refer to [BSI's AIS-31 guidelines](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Kryptografie/Zufallszahlengenerator/zufallszahlengenerator_node.html) for more information.

## Usage

For detailed instructions, refer to the big comment in the source file [here](https://github.com/jlxip/cgoldie/blob/master/cgoldie.c#L2-L6).

### Example

Here’s a simple example of how to use the `cgoldie` library in your project:

```c
#include "cgoldie.h"

// ...

cgoldie(shared_secret, private_key, public_key);
cgoldie(out, private_key, public_key);
    if (0 != memcmp(out, kat_sm_1o, 56)) {
        printf("This was unexpected\n");
        return 2;
    }

int main() {
    uint8_t private_key[56], public_key[56], shared_secret[56];
    cgoldie_keygen(private_key, public_key); // Generate keys
    cgoldie_keyexchange(shared_secret, private_key, public_key); // Exchange keys
    return 0;
}
```

### Repository Files

- **cgoldie.c**: Main implementation.
- **cgoldie.h**: Optional header file that defines the public functions.
- **kats.py**: Python script that generates the embedded test vectors.
- **test_main.c**: Entry point of the test program.
- **testall.sh**: Bash script that runs all tests with various compilation options.

## Status

This project is considered complete and is no longer actively developed.

## License

This project is public domain. You can use, modify, and distribute it without any restrictions.
