#ifndef UUID_JSON_PRINTER_H
#define UUID_JSON_PRINTER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_printer.h"
#include "flatcc/flatcc_prologue.h"

static void AzureIoTSecurity_UUID_print_json_struct(flatcc_json_printer_t *ctx, const void *p);

static void AzureIoTSecurity_UUID_print_json_struct(flatcc_json_printer_t *ctx, const void *p)
{
    flatcc_json_printer_uint8_array_struct_field(ctx, 0, p, 0, "value", 5, 16);
}

static inline int AzureIoTSecurity_UUID_print_json_as_root(flatcc_json_printer_t *ctx, const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_json_printer_struct_as_root(ctx, buf, bufsiz, fid, AzureIoTSecurity_UUID_print_json_struct);
}

#include "flatcc/flatcc_epilogue.h"
#endif /* UUID_JSON_PRINTER_H */