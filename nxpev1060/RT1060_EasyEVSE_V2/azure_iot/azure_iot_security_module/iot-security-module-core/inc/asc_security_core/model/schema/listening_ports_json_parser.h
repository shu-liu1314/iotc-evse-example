#ifndef LISTENING_PORTS_JSON_PARSER_H
#define LISTENING_PORTS_JSON_PARSER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_parser.h"
#ifndef PROTOCOL_JSON_PARSER_H
#include "protocol_json_parser.h"
#endif
#include "flatcc/flatcc_prologue.h"

static const char *AzureIoTSecurity_ListeningPortsCommon_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base);
static const char *AzureIoTSecurity_ListeningPortsCommon_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *AzureIoTSecurity_ListeningPortsV4_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base);
static const char *AzureIoTSecurity_ListeningPortsV4_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *AzureIoTSecurity_ListeningPortsV6_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base);
static const char *AzureIoTSecurity_ListeningPortsV6_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *AzureIoTSecurity_ListeningPorts_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *listening_ports_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *listening_ports_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *listening_ports_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate);

static const char *AzureIoTSecurity_ListeningPortsCommon_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base)
{
    int more;
    flatcc_builder_ref_t ref;
    void *pval;
    const char *mark;
    uint64_t w;

    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        w = flatcc_json_parser_symbol_part(buf, end);
        if (w == 0x6c6f63616c5f706f) { /* descend "local_po" */
            buf += 8;
            w = flatcc_json_parser_symbol_part(buf, end);
            if ((w & 0xffff000000000000) == 0x7274000000000000) { /* "rt" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 2);
                if (mark != buf) {
                    uint16_t val = 0;
                    static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                            listening_ports_local_AzureIoTSecurity_json_parser_enum,
                            listening_ports_global_json_parser_enum, 0 };
                    pval = (void *)((size_t)struct_base + 0);
                    buf = flatcc_json_parser_uint16(ctx, (mark = buf), end, &val);
                    if (mark == buf) {
                        buf = flatcc_json_parser_symbolic_uint16(ctx, (mark = buf), end, symbolic_parsers, &val);
                        if (buf == mark || buf == end) goto failed;
                    }
                    flatbuffers_uint16_write_to_pe(pval, val);
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "rt" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "rt" */
        } else { /* descend "local_po" */
            if (w == 0x70726f746f636f6c) { /* "protocol" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 8);
                if (mark != buf) {
                    int8_t val = 0;
                    static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                            AzureIoTSecurity_Protocol_parse_json_enum,
                            listening_ports_local_AzureIoTSecurity_json_parser_enum,
                            listening_ports_global_json_parser_enum, 0 };
                    pval = (void *)((size_t)struct_base + 2);
                    buf = flatcc_json_parser_int8(ctx, (mark = buf), end, &val);
                    if (mark == buf) {
                        buf = flatcc_json_parser_symbolic_int8(ctx, (mark = buf), end, symbolic_parsers, &val);
                        if (buf == mark || buf == end) goto failed;
                    }
                    flatbuffers_int8_write_to_pe(pval, val);
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "protocol" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "protocol" */
        } /* descend "local_po" */
        buf = flatcc_json_parser_object_end(ctx, buf, end , &more);
    }
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static const char *AzureIoTSecurity_ListeningPortsCommon_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    void *pval;

    *result = 0;
    if (!(pval = flatcc_builder_start_struct(ctx->ctx, 4, 2))) goto failed;
    buf = AzureIoTSecurity_ListeningPortsCommon_parse_json_struct_inline(ctx, buf, end, pval);
    if (buf == end || !(*result = flatcc_builder_end_struct(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_ListeningPortsCommon_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_struct_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_ListeningPortsCommon_parse_json_struct);
}

static const char *AzureIoTSecurity_ListeningPortsV4_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base)
{
    int more;
    flatcc_builder_ref_t ref;
    void *pval;
    const char *mark;
    uint64_t w;

    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        w = flatcc_json_parser_symbol_part(buf, end);
        if ((w & 0xffffffffffff0000) == 0x636f6d6d6f6e0000) { /* "common" */
            buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 6);
            if (mark != buf) {
                pval = (void *)((size_t)struct_base + 4);
                buf = AzureIoTSecurity_ListeningPortsCommon_parse_json_struct_inline(ctx, buf, end, pval);
            } else {
                goto pfguard1;
            }
        } else { /* "common" */
            goto pfguard1;
        } /* "common" */
        goto endpfguard1;
pfguard1:
        if (w == 0x6c6f63616c5f6164) { /* descend "local_ad" */
            buf += 8;
            w = flatcc_json_parser_symbol_part(buf, end);
            if ((w & 0xffffffffff000000) == 0x6472657373000000) { /* "dress" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 5);
                if (mark != buf) {
                    uint32_t val = 0;
                    static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                            listening_ports_local_AzureIoTSecurity_json_parser_enum,
                            listening_ports_global_json_parser_enum, 0 };
                    pval = (void *)((size_t)struct_base + 0);
                    buf = flatcc_json_parser_uint32(ctx, (mark = buf), end, &val);
                    if (mark == buf) {
                        buf = flatcc_json_parser_symbolic_uint32(ctx, (mark = buf), end, symbolic_parsers, &val);
                        if (buf == mark || buf == end) goto failed;
                    }
                    flatbuffers_uint32_write_to_pe(pval, val);
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "dress" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "dress" */
        } else { /* descend "local_ad" */
            buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
        } /* descend "local_ad" */
endpfguard1:
        (void)0;
        buf = flatcc_json_parser_object_end(ctx, buf, end , &more);
    }
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static const char *AzureIoTSecurity_ListeningPortsV4_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    void *pval;

    *result = 0;
    if (!(pval = flatcc_builder_start_struct(ctx->ctx, 8, 4))) goto failed;
    buf = AzureIoTSecurity_ListeningPortsV4_parse_json_struct_inline(ctx, buf, end, pval);
    if (buf == end || !(*result = flatcc_builder_end_struct(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_ListeningPortsV4_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_struct_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_ListeningPortsV4_parse_json_struct);
}

static const char *AzureIoTSecurity_ListeningPortsV6_parse_json_struct_inline(flatcc_json_parser_t *ctx, const char *buf, const char *end, void *struct_base)
{
    int more;
    flatcc_builder_ref_t ref;
    void *pval;
    const char *mark;
    uint64_t w;

    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        w = flatcc_json_parser_symbol_part(buf, end);
        if ((w & 0xffffffffffff0000) == 0x636f6d6d6f6e0000) { /* "common" */
            buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 6);
            if (mark != buf) {
                pval = (void *)((size_t)struct_base + 16);
                buf = AzureIoTSecurity_ListeningPortsCommon_parse_json_struct_inline(ctx, buf, end, pval);
            } else {
                goto pfguard1;
            }
        } else { /* "common" */
            goto pfguard1;
        } /* "common" */
        goto endpfguard1;
pfguard1:
        if (w == 0x6c6f63616c5f6164) { /* descend "local_ad" */
            buf += 8;
            w = flatcc_json_parser_symbol_part(buf, end);
            if ((w & 0xffffffffff000000) == 0x6472657373000000) { /* "dress" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 5);
                if (mark != buf) {
                    size_t count = 4;
                    uint32_t *base = (uint32_t *)((size_t)struct_base + 0);
                    buf = flatcc_json_parser_array_start(ctx, buf, end, &more);
                    while (more) {
                        uint32_t val = 0;
                        static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                                listening_ports_local_AzureIoTSecurity_json_parser_enum,
                                listening_ports_global_json_parser_enum, 0 };
                        buf = flatcc_json_parser_uint32(ctx, (mark = buf), end, &val);
                        if (mark == buf) {
                            buf = flatcc_json_parser_symbolic_uint32(ctx, (mark = buf), end, symbolic_parsers, &val);
                            if (buf == mark || buf == end) goto failed;
                        }
                        if (count) {
                            flatbuffers_uint32_write_to_pe(base, val);
                            --count;
                            ++base;
                        } else if (!(ctx->flags & flatcc_json_parser_f_skip_array_overflow)) {
                            return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_array_overflow);
                        }
                        buf = flatcc_json_parser_array_end(ctx, buf, end, &more);
                    }
                    if (count) {
                        if (ctx->flags & flatcc_json_parser_f_reject_array_underflow) {
                            return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_array_underflow);
                        }
                        memset(base, 0, count * sizeof(*base));
                    }
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "dress" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "dress" */
        } else { /* descend "local_ad" */
            buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
        } /* descend "local_ad" */
endpfguard1:
        (void)0;
        buf = flatcc_json_parser_object_end(ctx, buf, end , &more);
    }
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static const char *AzureIoTSecurity_ListeningPortsV6_parse_json_struct(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    void *pval;

    *result = 0;
    if (!(pval = flatcc_builder_start_struct(ctx->ctx, 20, 4))) goto failed;
    buf = AzureIoTSecurity_ListeningPortsV6_parse_json_struct_inline(ctx, buf, end, pval);
    if (buf == end || !(*result = flatcc_builder_end_struct(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_ListeningPortsV6_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_struct_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_ListeningPortsV6_parse_json_struct);
}

static const char *AzureIoTSecurity_ListeningPorts_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    int more;
    void *pval;
    flatcc_builder_ref_t ref, *pref;
    const char *mark;
    uint64_t w;

    *result = 0;
    if (flatcc_builder_start_table(ctx->ctx, 2)) goto failed;
    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        w = flatcc_json_parser_symbol_part(buf, end);
        if (w == 0x697076345f706f72) { /* descend "ipv4_por" */
            buf += 8;
            w = flatcc_json_parser_symbol_part(buf, end);
            if ((w & 0xffff000000000000) == 0x7473000000000000) { /* "ts" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 2);
                if (mark != buf) {
                    if (flatcc_builder_start_vector(ctx->ctx, 8, 4, UINT64_C(536870911))) goto failed;
                    buf = flatcc_json_parser_array_start(ctx, buf, end, &more);
                    while (more) {
                        if (!(pval = flatcc_builder_extend_vector(ctx->ctx, 1))) goto failed;
                        buf = AzureIoTSecurity_ListeningPortsV4_parse_json_struct_inline(ctx, buf, end, pval);
                        buf = flatcc_json_parser_array_end(ctx, buf, end, &more);
                    }
                    ref = flatcc_builder_end_vector(ctx->ctx);
                    if (!ref || !(pref = flatcc_builder_table_add_offset(ctx->ctx, 0))) goto failed;
                    *pref = ref;
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "ts" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "ts" */
        } else { /* descend "ipv4_por" */
            if (w == 0x697076365f706f72) { /* descend "ipv6_por" */
                buf += 8;
                w = flatcc_json_parser_symbol_part(buf, end);
                if ((w & 0xffff000000000000) == 0x7473000000000000) { /* "ts" */
                    buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 2);
                    if (mark != buf) {
                        if (flatcc_builder_start_vector(ctx->ctx, 20, 4, UINT64_C(214748364))) goto failed;
                        buf = flatcc_json_parser_array_start(ctx, buf, end, &more);
                        while (more) {
                            if (!(pval = flatcc_builder_extend_vector(ctx->ctx, 1))) goto failed;
                            buf = AzureIoTSecurity_ListeningPortsV6_parse_json_struct_inline(ctx, buf, end, pval);
                            buf = flatcc_json_parser_array_end(ctx, buf, end, &more);
                        }
                        ref = flatcc_builder_end_vector(ctx->ctx);
                        if (!ref || !(pref = flatcc_builder_table_add_offset(ctx->ctx, 1))) goto failed;
                        *pref = ref;
                    } else {
                        buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                    }
                } else { /* "ts" */
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                } /* "ts" */
            } else { /* descend "ipv6_por" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* descend "ipv6_por" */
        } /* descend "ipv4_por" */
        buf = flatcc_json_parser_object_end(ctx, buf, end, &more);
    }
    if (ctx->error) goto failed;
    if (!(*result = flatcc_builder_end_table(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_ListeningPorts_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_table_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_ListeningPorts_parse_json_table);
}

static const char *listening_ports_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    /* Scope has no enum / union types to look up. */
    return buf; /* unmatched; */
}

static const char *listening_ports_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    const char *unmatched = buf;
    const char *mark;
    uint64_t w;

    w = flatcc_json_parser_symbol_part(buf, end);
    if (w == 0x50726f746f636f6c) { /* "Protocol" */
        buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 8);
        if (buf != mark) {
            buf = AzureIoTSecurity_Protocol_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
        } else {
            return unmatched;
        }
    } else { /* "Protocol" */
        return unmatched;
    } /* "Protocol" */
    return buf;
}

static const char *listening_ports_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    const char *unmatched = buf;
    const char *mark;
    uint64_t w;

    w = flatcc_json_parser_symbol_part(buf, end);
    if (w == 0x417a757265496f54) { /* descend "AzureIoT" */
        buf += 8;
        w = flatcc_json_parser_symbol_part(buf, end);
        if (w == 0x5365637572697479) { /* descend "Security" */
            buf += 8;
            w = flatcc_json_parser_symbol_part(buf, end);
            if (w == 0x2e50726f746f636f) { /* descend ".Protoco" */
                buf += 8;
                w = flatcc_json_parser_symbol_part(buf, end);
                if ((w & 0xff00000000000000) == 0x6c00000000000000) { /* "l" */
                    buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 1);
                    if (buf != mark) {
                        buf = AzureIoTSecurity_Protocol_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                    } else {
                        return unmatched;
                    }
                } else { /* "l" */
                    return unmatched;
                } /* "l" */
            } else { /* descend ".Protoco" */
                return unmatched;
            } /* descend ".Protoco" */
        } else { /* descend "Security" */
            return unmatched;
        } /* descend "Security" */
    } else { /* descend "AzureIoT" */
        return unmatched;
    } /* descend "AzureIoT" */
    return buf;
}

#include "flatcc/flatcc_epilogue.h"
#endif /* LISTENING_PORTS_JSON_PARSER_H */
