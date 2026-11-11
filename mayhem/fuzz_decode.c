/*
 * Whole decoder stack: one Ethernet frame through ec_decode()'s own link-layer entry
 * (eth -> arp/ip/ip6/vlan/... -> tcp/udp/icmp -> the dissector registered for the port).
 */
#include "fuzz_common.h"
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_filter.h>
#include <ec_inject.h>
#include <ec_capture.h>
#include <ec_packet.h>
#include <stdlib.h>
#include <string.h>

/*
 * Stand-in for the APP_LAYER/PL_DEFAULT decoder (decode_data in ec_decode.c): the same dissector
 * dispatch, minus top_half_queue_add(), which would park a copy of every packet in an
 * unbounded queue nobody drains here. Afterwards the sessions the dissectors made for this
 * packet are dropped, so an input's outcome does not depend on earlier inputs.
 */
static FUNC_DECODER(fuzz_decode_data)
{
   int proto = 0;
   FUNC_DECODER_PTR(app_decoder);
   FUNC_DECODER_PTR(src_decoder) = NULL;
   FUNC_DECODER_PTR(dst_decoder) = NULL;

   if (po->flags & PO_DONT_DISSECT)
      return NULL;

   switch (po->L4.proto) {
      case NL_TYPE_TCP: proto = APP_LAYER_TCP; break;
      case NL_TYPE_UDP: proto = APP_LAYER_UDP; break;
   }

   if (proto) {
      app_decoder = get_decoder(proto, ntohs(po->L4.src));
      src_decoder = app_decoder;
      EXECUTE_DECODER(app_decoder);

      if (po->L4.src != po->L4.dst) {
         app_decoder = get_decoder(proto, ntohs(po->L4.dst));
         dst_decoder = app_decoder;
         EXECUTE_DECODER(app_decoder);
      }
   }

   hook_point(HOOK_DECODED, po);
   filter_packet(po);
   inject_split_data(po);
   hook_point(HOOK_FILTER, po);

   if (src_decoder)
      dissect_wipe_session(po, (void *)src_decoder);
   if (dst_decoder && dst_decoder != src_decoder)
      dissect_wipe_session(po, (void *)dst_decoder);

   return NULL;
}

/* the interface buffer ec_network.c allocates for captured packets (ec_network.c:76) */
static u_char *pbuf;
static size_t pbuf_size;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   (void)argc; (void)argv;
   fuzz_ec_init("fuzz_decode");

   EC_GBL_PCAP->dlt = IL_TYPE_ETH;
   EC_GBL_PCAP->align = get_alignment(IL_TYPE_ETH);
   EC_GBL_PCAP->snaplen = UINT16_MAX;

   pbuf_size = UINT16_MAX + EC_GBL_PCAP->align + 256;
   pbuf = calloc(pbuf_size, 1);

   del_decoder(APP_LAYER, PL_DEFAULT);
   add_decoder(APP_LAYER, PL_DEFAULT, fuzz_decode_data);
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   struct packet_object po;
   int len = 0;
   FUNC_DECODER_PTR(packet_decoder);

   /* ec_decode(): "Bad packet detected, skipping" above UINT16_MAX; the decoders take a u_int16 length */
   if (size >= EC_GBL_PCAP->snaplen)
      return -1;

   /* ec_decode(): copy at the media alignment into the zeroed interface buffer, NUL-terminated after the packet */
   memset(pbuf, 0, pbuf_size);
   memcpy(pbuf + EC_GBL_PCAP->align, data, size);
   pbuf[EC_GBL_PCAP->align + size] = 0;

   packet_create_object(&po, pbuf + EC_GBL_PCAP->align, size);

   packet_decoder = get_decoder(LINK_LAYER, EC_GBL_PCAP->dlt);
   packet_decoder(po.packet, size, &len, &po);

   packet_destroy_object(&po);
   fuzz_ec_drain();
   return 0;
}
