#ifndef LOG_READER_H
#define LOG_READER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#ifndef FLATBUFFERS_COMMON_READER_H
#include "flatbuffers_common_reader.h"
#endif
#include "flatcc/flatcc_flatbuffers.h"
#ifndef __alignas_is_defined
#include <stdalign.h>
#endif
#include "flatcc/flatcc_prologue.h"
#ifndef flatbuffers_identifier
#define flatbuffers_identifier 0
#endif
#ifndef flatbuffers_extension
#define flatbuffers_extension ".bin"
#endif


typedef const struct AzureIoTSecurity_Record_table *AzureIoTSecurity_Record_table_t;
typedef struct AzureIoTSecurity_Record_table *AzureIoTSecurity_Record_mutable_table_t;
typedef const flatbuffers_uoffset_t *AzureIoTSecurity_Record_vec_t;
typedef flatbuffers_uoffset_t *AzureIoTSecurity_Record_mutable_vec_t;
typedef const struct AzureIoTSecurity_Log_table *AzureIoTSecurity_Log_table_t;
typedef struct AzureIoTSecurity_Log_table *AzureIoTSecurity_Log_mutable_table_t;
typedef const flatbuffers_uoffset_t *AzureIoTSecurity_Log_vec_t;
typedef flatbuffers_uoffset_t *AzureIoTSecurity_Log_mutable_vec_t;
#ifndef AzureIoTSecurity_Record_file_identifier
#define AzureIoTSecurity_Record_file_identifier flatbuffers_identifier
#endif
/* deprecated, use AzureIoTSecurity_Record_file_identifier */
#ifndef AzureIoTSecurity_Record_identifier
#define AzureIoTSecurity_Record_identifier flatbuffers_identifier
#endif
#define AzureIoTSecurity_Record_type_hash ((flatbuffers_thash_t)0xb5e0a8b5)
#define AzureIoTSecurity_Record_type_identifier "\xb5\xa8\xe0\xb5"
#ifndef AzureIoTSecurity_Log_file_identifier
#define AzureIoTSecurity_Log_file_identifier flatbuffers_identifier
#endif
/* deprecated, use AzureIoTSecurity_Log_file_identifier */
#ifndef AzureIoTSecurity_Log_identifier
#define AzureIoTSecurity_Log_identifier flatbuffers_identifier
#endif
#define AzureIoTSecurity_Log_type_hash ((flatbuffers_thash_t)0x4ee428f2)
#define AzureIoTSecurity_Log_type_identifier "\xf2\x28\xe4\x4e"

typedef int8_t AzureIoTSecurity_Level_enum_t;
__flatbuffers_define_integer_type(AzureIoTSecurity_Level, AzureIoTSecurity_Level_enum_t, 8)
#define AzureIoTSecurity_Level_NOTSET ((AzureIoTSecurity_Level_enum_t)INT8_C(0))
#define AzureIoTSecurity_Level_FATAL ((AzureIoTSecurity_Level_enum_t)INT8_C(1))
#define AzureIoTSecurity_Level_ERROR ((AzureIoTSecurity_Level_enum_t)INT8_C(2))
#define AzureIoTSecurity_Level_WARN ((AzureIoTSecurity_Level_enum_t)INT8_C(3))
#define AzureIoTSecurity_Level_INFO ((AzureIoTSecurity_Level_enum_t)INT8_C(4))
#define AzureIoTSecurity_Level_DEBUG ((AzureIoTSecurity_Level_enum_t)INT8_C(5))

static inline const char *AzureIoTSecurity_Level_name(AzureIoTSecurity_Level_enum_t value)
{
    switch (value) {
    case AzureIoTSecurity_Level_NOTSET: return "NOTSET";
    case AzureIoTSecurity_Level_FATAL: return "FATAL";
    case AzureIoTSecurity_Level_ERROR: return "ERROR";
    case AzureIoTSecurity_Level_WARN: return "WARN";
    case AzureIoTSecurity_Level_INFO: return "INFO";
    case AzureIoTSecurity_Level_DEBUG: return "DEBUG";
    default: return "";
    }
}

static inline int AzureIoTSecurity_Level_is_known_value(AzureIoTSecurity_Level_enum_t value)
{
    switch (value) {
    case AzureIoTSecurity_Level_NOTSET: return 1;
    case AzureIoTSecurity_Level_FATAL: return 1;
    case AzureIoTSecurity_Level_ERROR: return 1;
    case AzureIoTSecurity_Level_WARN: return 1;
    case AzureIoTSecurity_Level_INFO: return 1;
    case AzureIoTSecurity_Level_DEBUG: return 1;
    default: return 0;
    }
}



struct AzureIoTSecurity_Record_table { uint8_t unused__; };

static inline size_t AzureIoTSecurity_Record_vec_len(AzureIoTSecurity_Record_vec_t vec)
__flatbuffers_vec_len(vec)
static inline AzureIoTSecurity_Record_table_t AzureIoTSecurity_Record_vec_at(AzureIoTSecurity_Record_vec_t vec, size_t i)
__flatbuffers_offset_vec_at(AzureIoTSecurity_Record_table_t, vec, i, 0)
__flatbuffers_table_as_root(AzureIoTSecurity_Record)

/**  The formatted log message */
__flatbuffers_define_string_field(0, AzureIoTSecurity_Record, message, 1)
/**  The level of the record defined in Level enum */
__flatbuffers_define_scalar_field(1, AzureIoTSecurity_Record, level, AzureIoTSecurity_Level, AzureIoTSecurity_Level_enum_t, INT8_C(0))
__flatbuffers_define_scalar_field(2, AzureIoTSecurity_Record, timestamp, flatbuffers_uint64, uint64_t, UINT64_C(0))
/**  The line number from which this record was written */
__flatbuffers_define_scalar_field(3, AzureIoTSecurity_Record, line, flatbuffers_uint32, uint32_t, UINT32_C(0))
/**  The file name from which this record was written */
__flatbuffers_define_string_field(4, AzureIoTSecurity_Record, filename, 1)

struct AzureIoTSecurity_Log_table { uint8_t unused__; };

static inline size_t AzureIoTSecurity_Log_vec_len(AzureIoTSecurity_Log_vec_t vec)
__flatbuffers_vec_len(vec)
static inline AzureIoTSecurity_Log_table_t AzureIoTSecurity_Log_vec_at(AzureIoTSecurity_Log_vec_t vec, size_t i)
__flatbuffers_offset_vec_at(AzureIoTSecurity_Log_table_t, vec, i, 0)
__flatbuffers_table_as_root(AzureIoTSecurity_Log)

__flatbuffers_define_vector_field(0, AzureIoTSecurity_Log, logs, AzureIoTSecurity_Record_vec_t, 0)


#include "flatcc/flatcc_epilogue.h"
#endif /* LOG_READER_H */
