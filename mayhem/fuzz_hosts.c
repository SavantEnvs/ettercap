/* The hosts-list file reader behind `ettercap -j <file>` (scan_load_hosts), fed a scratch file. */
#include "fuzz_common.h"
#include <ec_scan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   (void)argc; (void)argv;
   fuzz_ec_init("fuzz_hosts");
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   const char *tmp = getenv("TMPDIR");
   char path[4096];
   int fd;

   snprintf(path, sizeof(path), "%s/ec-hosts-XXXXXX", tmp && *tmp ? tmp : "/tmp");
   fd = mkstemp(path);
   if (fd < 0)
      return 0;
   if ((size_t)write(fd, data, size) != size) {
      close(fd);
      unlink(path);
      return 0;
   }
   close(fd);

   scan_load_hosts(path);

   unlink(path);
   del_hosts_list();
   fuzz_ec_drain();
   return 0;
}
