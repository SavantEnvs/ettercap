/*
 * One application-layer dissector on one TCP/UDP payload. The first three input bytes pick which
 * registered dissector (and which side of the connection its port is on); the rest is the payload.
 */
#include "fuzz_common.h"
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_packet.h>
#include <ec_inet.h>
#include <stdlib.h>
#include <string.h>

struct slot {
   u_int8 level;
   u_int16 port;
   FUNC_DECODER_PTR(fn);
};

/* the payload sits in a zeroed buffer the size of ettercap's interface buffer (ec_network.c:76) */
#define PBUF_SIZE (UINT16_MAX + 256)
static u_char pbuf[PBUF_SIZE];

static struct slot *slots;
static size_t nslots;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   static const u_int8 levels[] = { APP_LAYER_TCP, APP_LAYER_UDP };
   size_t l;
   u_int32 port;

   (void)argc; (void)argv;
   fuzz_ec_init("fuzz_dissect");

   for (l = 0; l < sizeof(levels); l++) {
      for (port = 1; port <= UINT16_MAX; port++) {
         void *fn = get_decoder(levels[l], port);
         if (fn == NULL)
            continue;
         slots = realloc(slots, (nslots + 1) * sizeof(*slots));
         slots[nslots].level = levels[l];
         slots[nslots].port = port;
         slots[nslots].fn = fn;
         nslots++;
      }
   }
   return nslots ? 0 : 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   static const u_char ipa[4] = { 10, 0, 0, 1 }, ipb[4] = { 10, 0, 0, 2 };
   static const u_char maca[6] = { 2, 0, 0, 0, 0, 1 }, macb[6] = { 2, 0, 0, 0, 0, 2 };
   struct packet_object po;
   const struct slot *sl;
   u_char *payload = pbuf;
   int len = 0;

   if (size < 3)
      return -1;

   sl = &slots[(((size_t)data[0] << 8) | data[1]) % nslots];
   data += 2; size -= 2;
   int to_server = data[0] & 1;
   data += 1; size -= 1;

   /* the decoders hand a dissector a payload of at most a u_int16 length */
   if (size > UINT16_MAX)
      return -1;

   memset(pbuf, 0, PBUF_SIZE);
   memcpy(payload, data, size);

   packet_create_object(&po, payload, size);

   memcpy(po.L2.src, to_server ? maca : macb, sizeof(maca));
   memcpy(po.L2.dst, to_server ? macb : maca, sizeof(maca));
   po.L2.proto = IL_TYPE_ETH;
   po.L3.proto = LL_TYPE_IP;
   ip_addr_init(&po.L3.src, AF_INET, (u_char *)(to_server ? ipa : ipb));
   ip_addr_init(&po.L3.dst, AF_INET, (u_char *)(to_server ? ipb : ipa));
   po.L3.ttl = 64;
   po.L3.payload_len = size;
   po.L4.proto = sl->level == APP_LAYER_TCP ? NL_TYPE_TCP : NL_TYPE_UDP;
   po.L4.src = htons(to_server ? 40000 : sl->port);
   po.L4.dst = htons(to_server ? sl->port : 40000);
   if (po.L4.proto == NL_TYPE_TCP)
      po.L4.flags = 0x18; /* PSH|ACK */
   po.DATA.data = payload;
   po.DATA.len = size;
   packet_disp_data(&po, payload, size);

   sl->fn(payload, size, &len, &po);

   dissect_wipe_session(&po, (void *)sl->fn);
   packet_destroy_object(&po);
   fuzz_ec_drain();
   return 0;
}
