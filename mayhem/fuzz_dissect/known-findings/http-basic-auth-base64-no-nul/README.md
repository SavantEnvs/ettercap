# HTTP dissector: any `Authorization: Basic` request overreads the decoded credentials

`crash-input.bin` (selector 4 = TCP/80, client to server) is an ordinary request carrying
`Authorization: Basic dXNlcjpwYXNz` (`user:pass`):

    ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 5 (strdup)
      #1 Parse_Basic_Auth  src/dissectors/ec_http.c:380
      #2 dissector_http    src/dissectors/ec_http.c:184
    allocated by base64decode  src/ec_utils.c:292

Cause: `base64decode()` callocs exactly `get_decode_len()` bytes and never NUL-terminates the result, then
`Parse_Basic_Auth` hands it to `ec_strtok()`/`strdup()` as a C string. Whenever the decoded token has no
spare byte (here 9 bytes for 9 characters) the string functions run past the allocation. Remote and
trivially triggered by any HTTP basic-auth request ettercap sniffs.
Fix: allocate `decodeLen + 1` in `base64decode()` (calloc already zero-fills it).

Reproduce: `/mayhem/fuzz_dissect-standalone crash-input.bin`
