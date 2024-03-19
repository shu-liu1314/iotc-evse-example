#ifndef MESSAGE_JSON_PARSER_H
#define MESSAGE_JSON_PARSER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_parser.h"
#ifndef EVENT_JSON_PARSER_H
#include "event_json_parser.h"
#endif
#include "flatcc/flatcc_prologue.h"

/*
 * Parses the default root table or struct of the schema and constructs a FlatBuffer.
 *
 * Builder `B` must be initialized. `ctx` can be null but will hold
 * hold detailed error info on return when available.
 * Returns 0 on success, or error code.
 * `flags` : 0 by default, `flatcc_json_parser_f_skip_unknown` silently
 * ignores unknown table and structs fields, and union types.
 */
static int message_parse_json(flatcc_builder_t *B, flatcc_json_parser_t *ctx,
        const char *buf, size_t bufsiz, int flags);

static const char *AzureIoTSecurity_Message_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result);
static const char *message_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *message_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
int *value_type, uint64_t *value, int *aggregate);
static const char *message_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate);

static const char *AzureIoTSecurity_Message_parse_json_table(flatcc_json_parser_t *ctx, const char *buf, const char *end, flatcc_builder_ref_t *result)
{
    int more;
    void *pval;
    flatcc_builder_ref_t ref, *pref;
    const char *mark;
    uint64_t w;

    *result = 0;
    if (flatcc_builder_start_table(ctx->ctx, 4)) goto failed;
    buf = flatcc_json_parser_object_start(ctx, buf, end, &more);
    while (more) {
        buf = flatcc_json_parser_symbol_start(ctx, buf, end);
        w = flatcc_json_parser_symbol_part(buf, end);
        if (w < 0x7365637572697479) { /* branch "security" */
            if ((w & 0xffffffffffff0000) == 0x6576656e74730000) { /* "events" */
                buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 6);
                if (mark != buf) {
                    if (flatcc_builder_start_offset_vector(ctx->ctx)) goto failed;
                    buf = flatcc_json_parser_array_start(ctx, buf, end, &more);
                    while (more) {
                        buf = AzureIoTSecurity_Event_parse_json_table(ctx, buf, end, &ref);
                        if (!ref || !(pref = flatcc_builder_extend_offset_vector(ctx->ctx, 1))) goto failed;
                        *pref = ref;
                        buf = flatcc_json_parser_array_end(ctx, buf, end, &more);
                    }
                    ref = flatcc_builder_end_offset_vector(ctx->ctx);
                    if (!ref || !(pref = flatcc_builder_table_add_offset(ctx->ctx, 3))) goto failed;
                    *pref = ref;
                } else {
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                }
            } else { /* "events" */
                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
            } /* "events" */
        } else { /* branch "security" */
            if (w == 0x7365637572697479) { /* descend "security" */
                buf += 8;
                w = flatcc_json_parser_symbol_part(buf, end);
                if (w == 0x5f6d6f64756c655f) { /* descend "_module_" */
                    buf += 8;
                    w = flatcc_json_parser_symbol_part(buf, end);
                    if ((w & 0xffffffffffffff00) == 0x76657273696f6e00) { /* "version" */
                        buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 7);
                        if (mark != buf) {
                            uint32_t val = 0;
                            static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                                    message_local_AzureIoTSecurity_json_parser_enum,
                                    message_global_json_parser_enum, 0 };
                            buf = flatcc_json_parser_uint32(ctx, (mark = buf), end, &val);
                            if (mark == buf) {
                                buf = flatcc_json_parser_symbolic_uint32(ctx, (mark = buf), end, symbolic_parsers, &val);
                                if (buf == mark || buf == end) goto failed;
                            }
                            if (val != 0 || (ctx->flags & flatcc_json_parser_f_force_add)) {
                                if (!(pval = flatcc_builder_table_add(ctx->ctx, 1, 4, 4))) goto failed;
                                flatbuffers_uint32_write_to_pe(pval, val);
                            }
                        } else {
                            buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                        }
                    } else { /* "version" */
                        if ((w & 0xffff000000000000) == 0x6964000000000000) { /* "id" */
                            buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 2);
                            if (mark != buf) {
                                buf = flatcc_json_parser_build_string(ctx, buf, end, &ref);
                                if (!ref || !(pref = flatcc_builder_table_add_offset(ctx->ctx, 0))) goto failed;
                                *pref = ref;
                            } else {
                                buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                            }
                        } else { /* "id" */
                            buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                        } /* "id" */
                    } /* "version" */
                } else { /* descend "_module_" */
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                } /* descend "_module_" */
            } else { /* descend "security" */
                if (w == 0x74696d657a6f6e65) { /* "timezone" */
                    buf = flatcc_json_parser_match_symbol(ctx, (mark = buf), end, 8);
                    if (mark != buf) {
                        int8_t val = 0;
                        static flatcc_json_parser_integral_symbol_f *symbolic_parsers[] = {
                                message_local_AzureIoTSecurity_json_parser_enum,
                                message_global_json_parser_enum, 0 };
                        buf = flatcc_json_parser_int8(ctx, (mark = buf), end, &val);
                        if (mark == buf) {
                            buf = flatcc_json_parser_symbolic_int8(ctx, (mark = buf), end, symbolic_parsers, &val);
                            if (buf == mark || buf == end) goto failed;
                        }
                        if (val != 0 || (ctx->flags & flatcc_json_parser_f_force_add)) {
                            if (!(pval = flatcc_builder_table_add(ctx->ctx, 2, 1, 1))) goto failed;
                            flatbuffers_int8_write_to_pe(pval, val);
                        }
                    } else {
                        buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                    }
                } else { /* "timezone" */
                    buf = flatcc_json_parser_unmatched_symbol(ctx, buf, end);
                } /* "timezone" */
            } /* descend "security" */
        } /* branch "security" */
        buf = flatcc_json_parser_object_end(ctx, buf, end, &more);
    }
    if (ctx->error) goto failed;
    if (!flatcc_builder_check_required_field(ctx->ctx, 3)
        ||  !flatcc_builder_check_required_field(ctx->ctx, 0)
    ) {
        buf = flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_required);
        goto failed;
    }
    if (!(*result = flatcc_builder_end_table(ctx->ctx))) goto failed;
    return buf;
failed:
    return flatcc_json_parser_set_error(ctx, buf, end, flatcc_json_parser_error_runtime);
}

static inline int AzureIoTSecurity_Message_parse_json_as_root(flatcc_builder_t *B, flatcc_json_parser_t *ctx, const char *buf, size_t bufsiz, int flags, const char *fid)
{
    return flatcc_json_parser_table_as_root(B, ctx, buf, bufsiz, flags, fid, AzureIoTSecurity_Message_parse_json_table);
}

static const char *message_local_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    /* Scope has no enum / union types to look up. */
    return buf; /* unmatched; */
}

static const char *message_local_AzureIoTSecurity_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
        int *value_type, uint64_t *value, int *aggregate)
{
    const char *unmatched = buf;
    const char *mark;
    uint64_t w;

    w = flatcc_json_parser_symbol_part(buf, end);
    if (w < 0x50726f6365737345) { /* branch "ProcessE" */
        if ((w & 0xffffffffffffff00) == 0x5061796c6f616400) { /* "Payload" */
            buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 7);
            if (buf != mark) {
                buf = AzureIoTSecurity_Payload_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
            } else {
                return unmatched;
            }
        } else { /* "Payload" */
            if ((w & 0xffffffffff000000) == 0x4c6576656c000000) { /* "Level" */
                buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 5);
                if (buf != mark) {
                    buf = AzureIoTSecurity_Level_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                } else {
                    return unmatched;
                }
            } else { /* "Level" */
                return unmatched;
            } /* "Level" */
        } /* "Payload" */
    } else { /* branch "ProcessE" */
        if (w < 0x50726f746f636f6c) { /* branch "Protocol" */
            if (w == 0x50726f6365737345) { /* descend "ProcessE" */
                buf += 8;
                w = flatcc_json_parser_symbol_part(buf, end);
                if (w == 0x76656e7454797065) { /* "ventType" */
                    buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 8);
                    if (buf != mark) {
                        buf = AzureIoTSecurity_ProcessEventType_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                    } else {
                        return unmatched;
                    }
                } else { /* "ventType" */
                    return unmatched;
                } /* "ventType" */
            } else { /* descend "ProcessE" */
                return unmatched;
            } /* descend "ProcessE" */
        } else { /* branch "Protocol" */
            if (w < 0x526573756c740000) { /* branch "Result" */
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
            } else { /* branch "Result" */
                if (w == 0x5365766572697479) { /* "Severity" */
                    buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 8);
                    if (buf != mark) {
                        buf = AzureIoTSecurity_Severity_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                    } else {
                        return unmatched;
                    }
                } else { /* "Severity" */
                    if ((w & 0xffffffffffff0000) == 0x526573756c740000) { /* "Result" */
                        buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 6);
                        if (buf != mark) {
                            buf = AzureIoTSecurity_Result_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                        } else {
                            return unmatched;
                        }
                    } else { /* "Result" */
                        return unmatched;
                    } /* "Result" */
                } /* "Severity" */
            } /* branch "Result" */
        } /* branch "Protocol" */
    } /* branch "ProcessE" */
    return buf;
}

static const char *message_global_json_parser_enum(flatcc_json_parser_t *ctx, const char *buf, const char *end,
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
            if (w < 0x2e50726f63657373) { /* branch ".Process" */
                if (w == 0x2e5061796c6f6164) { /* ".Payload" */
                    buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 8);
                    if (buf != mark) {
                        buf = AzureIoTSecurity_Payload_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                    } else {
                        return unmatched;
                    }
                } else { /* ".Payload" */
                    if ((w & 0xffffffffffff0000) == 0x2e4c6576656c0000) { /* ".Level" */
                        buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 6);
                        if (buf != mark) {
                            buf = AzureIoTSecurity_Level_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                        } else {
                            return unmatched;
                        }
                    } else { /* ".Level" */
                        return unmatched;
                    } /* ".Level" */
                } /* ".Payload" */
            } else { /* branch ".Process" */
                if (w < 0x2e50726f746f636f) { /* branch ".Protoco" */
                    if (w == 0x2e50726f63657373) { /* descend ".Process" */
                        buf += 8;
                        w = flatcc_json_parser_symbol_part(buf, end);
                        if (w == 0x4576656e74547970) { /* descend "EventTyp" */
                            buf += 8;
                            w = flatcc_json_parser_symbol_part(buf, end);
                            if ((w & 0xff00000000000000) == 0x6500000000000000) { /* "e" */
                                buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 1);
                                if (buf != mark) {
                                    buf = AzureIoTSecurity_ProcessEventType_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                                } else {
                                    return unmatched;
                                }
                            } else { /* "e" */
                                return unmatched;
                            } /* "e" */
                        } else { /* descend "EventTyp" */
                            return unmatched;
                        } /* descend "EventTyp" */
                    } else { /* descend ".Process" */
                        return unmatched;
                    } /* descend ".Process" */
                } else { /* branch ".Protoco" */
                    if (w < 0x2e526573756c7400) { /* branch ".Result" */
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
                    } else { /* branch ".Result" */
                        if ((w & 0xffffffffffffff00) == 0x2e526573756c7400) { /* ".Result" */
                            buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 7);
                            if (buf != mark) {
                                buf = AzureIoTSecurity_Result_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                            } else {
                                goto pfguard1;
                            }
                        } else { /* ".Result" */
                            goto pfguard1;
                        } /* ".Result" */
                        goto endpfguard1;
pfguard1:
                        if (w == 0x2e53657665726974) { /* descend ".Severit" */
                            buf += 8;
                            w = flatcc_json_parser_symbol_part(buf, end);
                            if ((w & 0xff00000000000000) == 0x7900000000000000) { /* "y" */
                                buf = flatcc_json_parser_match_scope(ctx, (mark = buf), end, 1);
                                if (buf != mark) {
                                    buf = AzureIoTSecurity_Severity_parse_json_enum(ctx, buf, end, value_type, value, aggregate);
                                } else {
                                    return unmatched;
                                }
                            } else { /* "y" */
                                return unmatched;
                            } /* "y" */
                        } else { /* descend ".Severit" */
                            return unmatched;
                        } /* descend ".Severit" */
endpfguard1:
                        (void)0;
                    } /* branch ".Result" */
                } /* branch ".Protoco" */
            } /* branch ".Process" */
        } else { /* descend "Security" */
            return unmatched;
        } /* descend "Security" */
    } else { /* descend "AzureIoT" */
        return unmatched;
    } /* descend "AzureIoT" */
    return buf;
}

static int message_parse_json(flatcc_builder_t *B, flatcc_json_parser_t *ctx,
        const char *buf, size_t bufsiz, int flags)
{
    flatcc_json_parser_t parser;
    flatcc_builder_ref_t root;

    ctx = ctx ? ctx : &parser;
    flatcc_json_parser_init(ctx, B, buf, buf + bufsiz, flags);
    if (flatcc_builder_start_buffer(B, 0, 0, 0)) return -1;
    AzureIoTSecurity_Message_parse_json_table(ctx, buf, buf + bufsiz, &root);
    if (ctx->error) {
        return ctx->error;
    }
    if (!flatcc_builder_end_buffer(B, root)) return -1;
    ctx->end_loc = buf;
    return 0;
}

#include "flatcc/flatcc_epilogue.h"
#endif /* MESSAGE_JSON_PARSER_H */
