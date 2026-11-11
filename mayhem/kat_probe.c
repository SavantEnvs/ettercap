/*
 * Known-answer probe for mayhem/test.sh: pushes fixed Ethernet frames through libettercap's real decoder
 * stack (eth -> ip/ip6/arp -> tcp/udp/icmp -> the dissector registered for the port) and prints what
 * ettercap extracted from each. test.sh compares the output byte for byte with the values written down there.
 * Links the shared library like ettercap itself does; built by build.sh with the project's normal flags.
 */
#include "fuzz_common.h"
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_packet.h>
#include <ec_inet.h>
#include <ec_inject.h>
#include <ec_capture.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *frame_name;

static const char *s(const char *p) { return p ? p : "-"; }

/* what decode_data() does for the dissectors, with the result printed instead of queued for the top half */
static FUNC_DECODER(kat_decode_data)
{
   char a[MAX_ASCII_ADDR_LEN], b[MAX_ASCII_ADDR_LEN];
   char ma[ETH_ASCII_ADDR_LEN], mb[ETH_ASCII_ADDR_LEN];
   int proto = 0;
   FUNC_DECODER_PTR(app_decoder);

   switch (po->L4.proto) {
      case NL_TYPE_TCP: proto = APP_LAYER_TCP; break;
      case NL_TYPE_UDP: proto = APP_LAYER_UDP; break;
   }
   if (proto) {
      app_decoder = get_decoder(proto, ntohs(po->L4.src));
      EXECUTE_DECODER(app_decoder);
      if (po->L4.src != po->L4.dst) {
         app_decoder = get_decoder(proto, ntohs(po->L4.dst));
         EXECUTE_DECODER(app_decoder);
      }
   }

   printf("%s: %s>%s %s>%s proto=%u %u>%u len=%u user=%s pass=%s banner=%s\n", frame_name,
          mac_addr_ntoa(po->L2.src, ma), mac_addr_ntoa(po->L2.dst, mb),
          ip_addr_ntoa(&po->L3.src, a), ip_addr_ntoa(&po->L3.dst, b),
          po->L4.proto, ntohs(po->L4.src), ntohs(po->L4.dst), po->DATA.len,
          s(po->DISSECTOR.user), s(po->DISSECTOR.pass), s(po->DISSECTOR.banner));
   dissect_wipe_session(po, (void *)get_decoder(proto, ntohs(po->L4.dst)));
   return NULL;
}

static unsigned short csum(const unsigned char *d, size_t n)
{
   unsigned long sum = 0;
   size_t i;
   for (i = 0; i + 1 < n; i += 2) sum += (d[i] << 8) | d[i + 1];
   if (n & 1) sum += d[n - 1] << 8;
   while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
   return (unsigned short)~sum;
}

/* Ethernet + IPv4 + TCP (PSH|ACK) or UDP around `payload` */
static size_t build(unsigned char *f, int udp, unsigned sport, unsigned dport, const char *payload, size_t plen)
{
   static const unsigned char macs[12] = { 2,0,0,0,0,2, 2,0,0,0,0,1 };
   size_t l4 = udp ? 8 : 20, ip = 20 + l4 + plen, n = 0;
   unsigned char *ipv4;

   memcpy(f, macs, 12); n = 12;
   f[n++] = 0x08; f[n++] = 0x00;
   ipv4 = f + n;
   memset(ipv4, 0, 20);
   ipv4[0] = 0x45; ipv4[2] = ip >> 8; ipv4[3] = ip; ipv4[6] = 0x40; ipv4[8] = 64; ipv4[9] = udp ? 17 : 6;
   ipv4[12] = 10; ipv4[15] = 1; ipv4[16] = 10; ipv4[19] = 2;
   ipv4[10] = csum(ipv4, 20) >> 8; ipv4[11] = csum(ipv4, 20);
   n += 20;
   memset(f + n, 0, l4);
   f[n] = sport >> 8; f[n + 1] = sport; f[n + 2] = dport >> 8; f[n + 3] = dport;
   if (udp) {
      f[n + 4] = (8 + plen) >> 8; f[n + 5] = 8 + plen;
   } else {
      f[n + 12] = 5 << 4; f[n + 13] = 0x18; f[n + 14] = 0x20;
   }
   n += l4;
   memcpy(f + n, payload, plen);
   return n + plen;
}

#define FEED(name, udp, sport, dport, lit) feed(name, udp, sport, dport, lit, sizeof(lit) - 1)
static void feed(const char *name, int udp, unsigned sport, unsigned dport, const char *payload, size_t plen)
{
   unsigned char frame[512];
   struct packet_object po;
   int len = 0;
   size_t n = build(frame, udp, sport, dport, payload, plen);
   u_char *pbuf = calloc(1, n + 256);
   FUNC_DECODER_PTR(packet_decoder);

   memcpy(pbuf, frame, n);
   frame_name = name;
   packet_create_object(&po, pbuf, n);
   packet_decoder = get_decoder(LINK_LAYER, EC_GBL_PCAP->dlt);
   packet_decoder(po.packet, n, &len, &po);
   packet_destroy_object(&po);
   fuzz_ec_drain();
   free(pbuf);
}

int main(void)
{
   fuzz_ec_init("kat_probe");
   EC_GBL_PCAP->dlt = IL_TYPE_ETH;
   EC_GBL_PCAP->align = get_alignment(IL_TYPE_ETH);
   EC_GBL_PCAP->snaplen = UINT16_MAX;
   del_decoder(APP_LAYER, PL_DEFAULT);
   add_decoder(APP_LAYER, PL_DEFAULT, kat_decode_data);

   FEED("imap-login", 0, 40002, 143, "a1 LOGIN alice hunter2\r\n");
   FEED("http-get", 0, 40005, 80, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
   FEED("imap-plain", 0, 40007, 143, "a2 LOGIN bob \"p w\"\r\n");
   FEED("snmp", 1, 40009, 161, "\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x7a\x69\xf1\xa5\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00");
   FEED("irc", 0, 40010, 6667, "PASS secret\r\nNICK bob\r\n");
   FEED("dns-query", 1, 40003, 53, "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x01\x00\x01");
   return 0;
}
