#ifndef HEARTBEAT_JSON_PRINTER_H
#define HEARTBEAT_JSON_PRINTER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_printer.h"
#include "flatcc/flatcc_prologue.h"

static void AzureIoTSecurity_Heartbeat_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td);

static void AzureIoTSecurity_Heartbeat_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td)
{
}

static inline int AzureIoTSecurity_Heartbeat_print_json_as_root(flatcc_json_printer_t *ctx, const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_json_printer_table_as_root(ctx, buf, bufsiz, fid, AzureIoTSecurity_Heartbeat_print_json_table);
}

#include "flatcc/flatcc_epilogue.h"
#endif /* HEARTBEAT_JSON_PRINTER_H */
