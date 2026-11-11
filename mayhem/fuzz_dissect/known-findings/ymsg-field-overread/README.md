# Yahoo Messenger dissector: field scan runs past the payload

`crash-input.bin` (selector 38 = TCP/5050, client to server) is a short, otherwise well-formed YMSG packet:

    ERROR: AddressSanitizer: heap-buffer-overflow
      #0 dissector_ymsg  src/dissectors/ec_ymsg.c:125

Cause: `for (q = ptr; *q != 0xc0 && q < end; q++)` dereferences before the bound test, and `ptr = q + 5`
(skip separators) moves past `end` without a check, so the next scan starts outside the `len + 1` byte
`disp_data` buffer. Same class as `../ymsg-memcmp-short-payload`.
Fix: test `q < end` first and verify `q + 5 <= end` before advancing.

Reproduce: `/mayhem/fuzz_dissect-standalone crash-input.bin`
