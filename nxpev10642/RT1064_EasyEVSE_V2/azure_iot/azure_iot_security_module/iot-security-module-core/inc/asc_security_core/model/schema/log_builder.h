#ifndef LOG_BUILDER_H
#define LOG_BUILDER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#ifndef LOG_READER_H
#include "log_reader.h"
#endif
#ifndef FLATBUFFERS_COMMON_BUILDER_H
#include "flatbuffers_common_builder.h"
#endif
#include "flatcc/flatcc_prologue.h"
#ifndef flatbuffers_identifier
#define flatbuffers_identifier 0
#endif
#ifndef flatbuffers_extension
#define flatbuffers_extension ".bin"
#endif

#define __AzureIoTSecurity_Level_formal_args , AzureIoTSecurity_Level_enum_t v0
#define __AzureIoTSecurity_Level_call_args , v0
__flatbuffers_build_scalar(flatbuffers_, AzureIoTSecurity_Level, AzureIoTSecurity_Level_enum_t)

static const flatbuffers_voffset_t __AzureIoTSecurity_Record_required[] = { 0, 4, 0 };
typedef flatbuffers_ref_t AzureIoTSecurity_Record_ref_t;
static AzureIoTSecurity_Record_ref_t AzureIoTSecurity_Record_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Record_table_t t);
__flatbuffers_build_table(flatbuffers_, AzureIoTSecurity_Record, 5)

static const flatbuffers_voffset_t __AzureIoTSecurity_Log_required[] = { 0 };
typedef flatbuffers_ref_t AzureIoTSecurity_Log_ref_t;
static AzureIoTSecurity_Log_ref_t AzureIoTSecurity_Log_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Log_table_t t);
__flatbuffers_build_table(flatbuffers_, AzureIoTSecurity_Log, 1)

#define __AzureIoTSecurity_Record_formal_args ,\
  flatbuffers_string_ref_t v0, AzureIoTSecurity_Level_enum_t v1, uint64_t v2, uint32_t v3, flatbuffers_string_ref_t v4
#define __AzureIoTSecurity_Record_call_args ,\
  v0, v1, v2, v3, v4
static inline AzureIoTSecurity_Record_ref_t AzureIoTSecurity_Record_create(flatbuffers_builder_t *B __AzureIoTSecurity_Record_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, AzureIoTSecurity_Record, AzureIoTSecurity_Record_file_identifier, AzureIoTSecurity_Record_type_identifier)

#define __AzureIoTSecurity_Log_formal_args , AzureIoTSecurity_Record_vec_ref_t v0
#define __AzureIoTSecurity_Log_call_args , v0
static inline AzureIoTSecurity_Log_ref_t AzureIoTSecurity_Log_create(flatbuffers_builder_t *B __AzureIoTSecurity_Log_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, AzureIoTSecurity_Log, AzureIoTSecurity_Log_file_identifier, AzureIoTSecurity_Log_type_identifier)

__flatbuffers_build_string_field(0, flatbuffers_, AzureIoTSecurity_Record_message, AzureIoTSecurity_Record)
__flatbuffers_build_scalar_field(1, flatbuffers_, AzureIoTSecurity_Record_level, AzureIoTSecurity_Level, AzureIoTSecurity_Level_enum_t, 1, 1, INT8_C(0), AzureIoTSecurity_Record)
__flatbuffers_build_scalar_field(2, flatbuffers_, AzureIoTSecurity_Record_timestamp, flatbuffers_uint64, uint64_t, 8, 8, UINT64_C(0), AzureIoTSecurity_Record)
__flatbuffers_build_scalar_field(3, flatbuffers_, AzureIoTSecurity_Record_line, flatbuffers_uint32, uint32_t, 4, 4, UINT32_C(0), AzureIoTSecurity_Record)
__flatbuffers_build_string_field(4, flatbuffers_, AzureIoTSecurity_Record_filename, AzureIoTSecurity_Record)

static inline AzureIoTSecurity_Record_ref_t AzureIoTSecurity_Record_create(flatbuffers_builder_t *B __AzureIoTSecurity_Record_formal_args)
{
    if (AzureIoTSecurity_Record_start(B)
        || AzureIoTSecurity_Record_timestamp_add(B, v2)
        || AzureIoTSecurity_Record_message_add(B, v0)
        || AzureIoTSecurity_Record_line_add(B, v3)
        || AzureIoTSecurity_Record_filename_add(B, v4)
        || AzureIoTSecurity_Record_level_add(B, v1)) {
        return 0;
    }
    return AzureIoTSecurity_Record_end(B);
}

static AzureIoTSecurity_Record_ref_t AzureIoTSecurity_Record_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Record_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (AzureIoTSecurity_Record_start(B)
        || AzureIoTSecurity_Record_timestamp_pick(B, t)
        || AzureIoTSecurity_Record_message_pick(B, t)
        || AzureIoTSecurity_Record_line_pick(B, t)
        || AzureIoTSecurity_Record_filename_pick(B, t)
        || AzureIoTSecurity_Record_level_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, AzureIoTSecurity_Record_end(B));
}

__flatbuffers_build_table_vector_field(0, flatbuffers_, AzureIoTSecurity_Log_logs, AzureIoTSecurity_Record, AzureIoTSecurity_Log)

static inline AzureIoTSecurity_Log_ref_t AzureIoTSecurity_Log_create(flatbuffers_builder_t *B __AzureIoTSecurity_Log_formal_args)
{
    if (AzureIoTSecurity_Log_start(B)
        || AzureIoTSecurity_Log_logs_add(B, v0)) {
        return 0;
    }
    return AzureIoTSecurity_Log_end(B);
}

static AzureIoTSecurity_Log_ref_t AzureIoTSecurity_Log_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Log_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (AzureIoTSecurity_Log_start(B)
        || AzureIoTSecurity_Log_logs_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, AzureIoTSecurity_Log_end(B));
}

#include "flatcc/flatcc_epilogue.h"
#endif /* LOG_BUILDER_H */
