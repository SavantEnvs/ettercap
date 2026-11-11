# telnet: `skip_telnet_command` reads past the packet payload

`crash-input.bin` is a raw Ethernet frame (IPv4/TCP, port 23) that `mayhem/fuzz_decode` aborts on:

    ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
      #0 skip_telnet_command   src/dissectors/ec_telnet.c:275
      #1 dissector_telnet      src/dissectors/ec_telnet.c:82
      #3 decode_tcp            src/protocols/ec_tcp.c:295

Cause: the loop tests `**ptr == 0xff && *ptr < end` (dereference first, bound second), and the
sub-option branch advances `*ptr += 2` past `end` without a check, so a payload ending in `0xff 0xfa ...`
or a lone `0xff` makes the next dereference run off the 1-byte-padded `DATA.disp_data` buffer.
Impact: remote out-of-bounds read of attacker-controlled sniffed traffic (crash of the sniffer).
Fix: check `*ptr < end` before every dereference/advance (`while (*ptr < end && **ptr == 0xff)`, and
clamp `*ptr += 2` to `end`).

Reproduce: `/mayhem/fuzz_decode-standalone crash-input.bin`
