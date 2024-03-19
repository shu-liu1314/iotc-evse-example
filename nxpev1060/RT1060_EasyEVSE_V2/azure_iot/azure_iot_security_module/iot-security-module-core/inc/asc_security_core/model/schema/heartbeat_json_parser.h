#ifndef HEARTBEAT_JSON_PARSER_H
#define HEARTBEAT_JSON_PARSER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_parser.h"
#include "flatcc/flatcc_prologue.h"

static const char *AzureIoTSecurity_Heartbeat_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *heartbeat_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *heartbeat_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *heartbeat_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate);

static const char *AzureIoTSecurity_Heartbeat_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    int more;

    *result = 0;
    if (flatcc_builder_start_table(ctx->ctx, 0)) goto failed;
    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        /* Table has no fields. */
        buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
        buf = flatcc_json_parser_object_end(ctx, buf, end, &more);
    }
    if (ctx->error) goto failed;
    if (!(*result = flatcc_builder_end_table(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_Heartbeat_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_table_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_Heartbeat_parse_json_table);
}

static const char *heartbeat_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    /* Scope has no enum / union types to look up. */
    return buf; /* unmatched; */
}

static const char *heartbeat_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    /* Scope has no enum / union types to look up. */
    return buf; /* unmatched; */
}

static const char *heartbeat_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    /* Global scope has no enum / union types to look up. */
    return buf; /* unmatched; */
}

#include "flatcc/flatcc_epilogue.h"
#endif /* HEARTBEAT_JSON_PARSER_H */
