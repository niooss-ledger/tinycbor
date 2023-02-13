/* Fuzz CBOR parser
 *
 * Usage:
clang -Wall -Wextra -O2 -ggdb -fsanitize=address,undefined,fuzzer -o fuzz_cbor_parser fuzz_cbor_parser.c src/cborparser.c src/cborpretty.c
mkdir -p corpus_fuzz_cbor_parser && ./fuzz_cbor_parser corpus_fuzz_cbor_parser

 * With code coverage:
clang -Wall -Wextra -O0 -ggdb -fprofile-instr-generate -fcoverage-mapping -fsanitize=address,undefined,fuzzer -o fuzz_cbor_parser_coverage fuzz_cbor_parser.c src/cborparser.c src/cborpretty.c
./fuzz_cbor_parser_coverage corpus_fuzz_cbor_parser/ *
llvm-profdata merge --sparse default.profraw -o default.profdata
llvm-cov show fuzz_cbor_parser_coverage -instr-profile=default.profdata -show-line-counts-or-regions -output-dir=html-coverage -format=html

 * With AFL++ : (cf. https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
 * podman pull docker.io/aflplusplus/aflplusplus
 * podman run --rm -it -v "$(pwd):/src" -w /src --cap-add=CAP_SYS_PTRACE docker.io/aflplusplus/aflplusplus
apt update && apt install -y libcjson-dev
make CC='clang -Wall -Wextra -O2 -ggdb -fsanitize=address,undefined'
afl-clang-lto -Wall -Wextra -O2 -ggdb -fsanitize=address,undefined,fuzzer -o fuzz_cbor_parser fuzz_cbor_parser.c src/cborparser.c src/cborpretty.c
mkdir -p fuzz_inputs fuzz_outputs
cat /dev/null > fuzz_inputs/empty
echo '""' | ./bin/json2cbor > fuzz_inputs/empty_string
echo '[1,"hello",42.5]' | ./bin/json2cbor > fuzz_inputs/array

afl-fuzz -i fuzz_inputs -o fuzz_outputs -- ./fuzz_cbor_parser
 */
#include <stdarg.h>
#include <stdint.h>

#include "src/cbor.h"


static __attribute__((format(printf, 2, 3)))
CborError callback_cbor_pretty_printf(void *out __attribute__((unused)), const char *fmt, ...)
{
    char buffer[1];
    int n;

    va_list list;
    va_start(list, fmt);
    n = vsnprintf(buffer, sizeof(buffer), fmt, list);
    va_end(list);

    return n < 0 ? CborErrorIO : CborNoError;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    CborParser parser;
    CborValue value;
    CborError err;

    err = cbor_parser_init(data, size, 0, &parser, &value);
    if (err != CborNoError) {
        return 0;
    }

/*
    // Optionally fuzz the validators too
    err = cbor_value_validate_basic(&value);
    if (err != CborNoError) {
        return 0;
    }

    err = cbor_value_validate(&value, CborValidateStrictest);
    if (err != CborNoError) {
        return 0;
    }
*/

    err = cbor_value_to_pretty_stream(callback_cbor_pretty_printf, NULL, &value, CborPrettyDefaultFlags);
    if (err != CborNoError) {
        return 0;
    }

    return 0;
}
