# Yahoo Messenger dissector (and others) compare the payload before checking its length

`crash-input.bin` is the `mayhem/fuzz_dissect` input (2-byte dissector selector, 1-byte direction, payload)
that selects `dissector_ymsg` with a 1-byte payload:

    ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 4 (memcmp)
      #2 dissector_ymsg   src/dissectors/ec_ymsg.c:61

Cause: `if (PACKET->DATA.len == 0 || memcmp(ptr, "YMSG", 4))` reads four bytes from `disp_data` whatever the
length is (the buffer is exactly `len + 1` bytes, `packet_disp_data()` in ec_packet.c:72). The same pattern is
in `dissector_mysql` (ec_mysql.c:98, `memcmp(ptr + 1, "\x00\x00\x00\x0a\x33\x2e", 6)`) and other dissectors
that `memcmp` a magic before looking at `DATA.len`. The sniffer hands them any TCP/UDP payload on the port, so
any host can trigger it. `mayhem/fuzz_decode` reaches the same family end to end (see its `known-findings/`).
Fix: `if (PACKET->DATA.len < 4 || memcmp(ptr, "YMSG", 4))` (and the matching minimum length elsewhere).

Reproduce: `/mayhem/fuzz_dissect-standalone crash-input.bin`
