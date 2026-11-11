/* Shared libettercap bring-up for the harnesses: globals, a silent UI sink, per-input message drain. */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <ec.h>
#include <ec_libettercap.h>
#include <ec_globals.h>
#include <ec_ui.h>
#include <limits.h>

static void sink_msg(const char *msg) { (void)msg; }

static void fuzz_ec_init(const char *name)
{
   libettercap_init((char *)name, "0.0.0");
   /* the text UI would print every message; take them off the queue instead */
   EC_GBL_UI->msg = sink_msg;
   EC_GBL_UI->error = sink_msg;
   EC_GBL_UI->initialized = 1;
}

static void fuzz_ec_drain(void)
{
   ui_msg_flush(INT_MAX);
}

#endif
