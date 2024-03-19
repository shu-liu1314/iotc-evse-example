#ifndef BASELINE_BUILDER_H
#define BASELINE_BUILDER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#ifndef BASELINE_READER_H
#include "baseline_reader.h"
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

#define __AzureIoTSecurity_Result_formal_args , AzureIoTSecurity_Result_enum_t v0
#define __AzureIoTSecurity_Result_call_args , v0
__flatbuffers_build_scalar(flatbuffers_, AzureIoTSecurity_Result, AzureIoTSecurity_Result_enum_t)
#define __AzureIoTSecurity_Severity_formal_args , AzureIoTSecurity_Severity_enum_t v0
#define __AzureIoTSecurity_Severity_call_args , v0
__flatbuffers_build_scalar(flatbuffers_, AzureIoTSecurity_Severity, AzureIoTSecurity_Severity_enum_t)

static const flatbuffers_voffset_t __AzureIoTSecurity_BaselineCheck_required[] = { 0, 0 };
typedef flatbuffers_ref_t AzureIoTSecurity_BaselineCheck_ref_t;
static AzureIoTSecurity_BaselineCheck_ref_t AzureIoTSecurity_BaselineCheck_clone(flatbuffers_builder_t *B, AzureIoTSecurity_BaselineCheck_table_t t);
__flatbuffers_build_table(flatbuffers_, AzureIoTSecurity_BaselineCheck, 6)

static const flatbuffers_voffset_t __AzureIoTSecurity_Baseline_required[] = { 0 };
typedef flatbuffers_ref_t AzureIoTSecurity_Baseline_ref_t;
static AzureIoTSecurity_Baseline_ref_t AzureIoTSecurity_Baseline_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Baseline_table_t t);
__flatbuffers_build_table(flatbuffers_, AzureIoTSecurity_Baseline, 1)

#define __AzureIoTSecurity_BaselineCheck_formal_args ,\
  flatbuffers_string_ref_t v0, AzureIoTSecurity_Result_enum_t v1, flatbuffers_string_ref_t v2, flatbuffers_string_ref_t v3, AzureIoTSecurity_Severity_enum_t v4, flatbuffers_string_ref_t v5
#define __AzureIoTSecurity_BaselineCheck_call_args ,\
  v0, v1, v2, v3, v4, v5
static inline AzureIoTSecurity_BaselineCheck_ref_t AzureIoTSecurity_BaselineCheck_create(flatbuffers_builder_t *B __AzureIoTSecurity_BaselineCheck_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, AzureIoTSecurity_BaselineCheck, AzureIoTSecurity_BaselineCheck_file_identifier, AzureIoTSecurity_BaselineCheck_type_identifier)

#define __AzureIoTSecurity_Baseline_formal_args , AzureIoTSecurity_BaselineCheck_vec_ref_t v0
#define __AzureIoTSecurity_Baseline_call_args , v0
static inline AzureIoTSecurity_Baseline_ref_t AzureIoTSecurity_Baseline_create(flatbuffers_builder_t *B __AzureIoTSecurity_Baseline_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, AzureIoTSecurity_Baseline, AzureIoTSecurity_Baseline_file_identifier, AzureIoTSecurity_Baseline_type_identifier)

__flatbuffers_build_string_field(0, flatbuffers_, AzureIoTSecurity_BaselineCheck_id, AzureIoTSecurity_BaselineCheck)
__flatbuffers_build_scalar_field(1, flatbuffers_, AzureIoTSecurity_BaselineCheck_result, AzureIoTSecurity_Result, AzureIoTSecurity_Result_enum_t, 1, 1, INT8_C(0), AzureIoTSecurity_BaselineCheck)
__flatbuffers_build_string_field(2, flatbuffers_, AzureIoTSecurity_BaselineCheck_error, AzureIoTSecurity_BaselineCheck)
__flatbuffers_build_string_field(3, flatbuffers_, AzureIoTSecurity_BaselineCheck_description, AzureIoTSecurity_BaselineCheck)
__flatbuffers_build_scalar_field(4, flatbuffers_, AzureIoTSecurity_BaselineCheck_severity, AzureIoTSecurity_Severity, AzureIoTSecurity_Severity_enum_t, 1, 1, INT8_C(0), AzureIoTSecurity_BaselineCheck)
__flatbuffers_build_string_field(5, flatbuffers_, AzureIoTSecurity_BaselineCheck_remediation, AzureIoTSecurity_BaselineCheck)

static inline AzureIoTSecurity_BaselineCheck_ref_t AzureIoTSecurity_BaselineCheck_create(flatbuffers_builder_t *B __AzureIoTSecurity_BaselineCheck_formal_args)
{
    if (AzureIoTSecurity_BaselineCheck_start(B)
        || AzureIoTSecurity_BaselineCheck_id_add(B, v0)
        || AzureIoTSecurity_BaselineCheck_error_add(B, v2)
        || AzureIoTSecurity_BaselineCheck_description_add(B, v3)
        || AzureIoTSecurity_BaselineCheck_remediation_add(B, v5)
        || AzureIoTSecurity_BaselineCheck_result_add(B, v1)
        || AzureIoTSecurity_BaselineCheck_severity_add(B, v4)) {
        return 0;
    }
    return AzureIoTSecurity_BaselineCheck_end(B);
}

static AzureIoTSecurity_BaselineCheck_ref_t AzureIoTSecurity_BaselineCheck_clone(flatbuffers_builder_t *B, AzureIoTSecurity_BaselineCheck_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (AzureIoTSecurity_BaselineCheck_start(B)
        || AzureIoTSecurity_BaselineCheck_id_pick(B, t)
        || AzureIoTSecurity_BaselineCheck_error_pick(B, t)
        || AzureIoTSecurity_BaselineCheck_description_pick(B, t)
        || AzureIoTSecurity_BaselineCheck_remediation_pick(B, t)
        || AzureIoTSecurity_BaselineCheck_result_pick(B, t)
        || AzureIoTSecurity_BaselineCheck_severity_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, AzureIoTSecurity_BaselineCheck_end(B));
}

__flatbuffers_build_table_vector_field(0, flatbuffers_, AzureIoTSecurity_Baseline_baseline_checks, AzureIoTSecurity_BaselineCheck, AzureIoTSecurity_Baseline)

static inline AzureIoTSecurity_Baseline_ref_t AzureIoTSecurity_Baseline_create(flatbuffers_builder_t *B __AzureIoTSecurity_Baseline_formal_args)
{
    if (AzureIoTSecurity_Baseline_start(B)
        || AzureIoTSecurity_Baseline_baseline_checks_add(B, v0)) {
        return 0;
    }
    return AzureIoTSecurity_Baseline_end(B);
}

static AzureIoTSecurity_Baseline_ref_t AzureIoTSecurity_Baseline_clone(flatbuffers_builder_t *B, AzureIoTSecurity_Baseline_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (AzureIoTSecurity_Baseline_start(B)
        || AzureIoTSecurity_Baseline_baseline_checks_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, AzureIoTSecurity_Baseline_end(B));
}

#include "flatcc/flatcc_epilogue.h"
#endif /* BASELINE_BUILDER_H */
