#ifndef LISTENING_PORTS_BUILDER_H
#define LISTENING_PORTS_BUILDER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#ifndef LISTENING_PORTS_READER_H
#include "listening_ports_reader.h"
#endif
#ifndef FLATBUFFERS_COMMON_BUILDER_H
#include "flatbuffers_common_builder.h"
#endif
#ifndef PROTOCOL_BUILDER_H
#include "protocol_builder.h"
#endif
#include "flatcc/flatcc_prologue.h"
#ifndef flatbuffers_identifier
#define flatbuffers_identifier 0
#endif
#ifndef flatbuffers_extension
#define flatbuffers_extension ".bin"
#endif

#define __AzureIoTSecurity_ListeningPortsCommon_formal_args , uint16_t v0, AzureIoTSecurity_Protocol_enum_t v1
#define __AzureIoTSecurity_ListeningPortsCommon_call_args , v0, v1
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_assign(AzureIoTSecurity_ListeningPortsCommon_t *p, uint16_t v0, AzureIoTSecurity_Protocol_enum_t v1)
{ p->local_port = v0; p->protocol = v1;
  return p; }
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_copy(AzureIoTSecurity_ListeningPortsCommon_t *p, const AzureIoTSecurity_ListeningPortsCommon_t *p2)
{ p->local_port = p2->local_port; p->protocol = p2->protocol;
  return p; }
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_assign_to_pe(AzureIoTSecurity_ListeningPortsCommon_t *p, uint16_t v0, AzureIoTSecurity_Protocol_enum_t v1)
{ flatbuffers_uint16_assign_to_pe(&p->local_port, v0); p->protocol = v1;
  return p; }
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_copy_to_pe(AzureIoTSecurity_ListeningPortsCommon_t *p, const AzureIoTSecurity_ListeningPortsCommon_t *p2)
{ flatbuffers_uint16_copy_to_pe(&p->local_port, &p2->local_port); p->protocol = p2->protocol;
  return p; }
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_assign_from_pe(AzureIoTSecurity_ListeningPortsCommon_t *p, uint16_t v0, AzureIoTSecurity_Protocol_enum_t v1)
{ flatbuffers_uint16_assign_from_pe(&p->local_port, v0); p->protocol = v1;
  return p; }
static inline AzureIoTSecurity_ListeningPortsCommon_t *AzureIoTSecurity_ListeningPortsCommon_copy_from_pe(AzureIoTSecurity_ListeningPortsCommon_t *p, const AzureIoTSecurity_ListeningPortsCommon_t *p2)
{ flatbuffers_uint16_copy_from_pe(&p->local_port, &p2->local_port); p->protocol = p2->protocol;
  return p; }
__flatbuffers_build_struct(flatbuffers_, AzureIoTSecurity_ListeningPortsCommon, 4, 2, AzureIoTSecurity_ListeningPortsCommon_file_identifier, AzureIoTSecurity_ListeningPortsCommon_type_identifier)
__flatbuffers_define_fixed_array_primitives(flatbuffers_, AzureIoTSecurity_ListeningPortsCommon, AzureIoTSecurity_ListeningPortsCommon_t)

#define __AzureIoTSecurity_ListeningPortsV4_formal_args , uint32_t v0, uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2
#define __AzureIoTSecurity_ListeningPortsV4_call_args , v0, v1, v2
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_assign(AzureIoTSecurity_ListeningPortsV4_t *p, uint32_t v0, uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ p->local_address = v0; AzureIoTSecurity_ListeningPortsCommon_assign(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_copy(AzureIoTSecurity_ListeningPortsV4_t *p, const AzureIoTSecurity_ListeningPortsV4_t *p2)
{ p->local_address = p2->local_address; AzureIoTSecurity_ListeningPortsCommon_copy(&p->common, &p2->common);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_assign_to_pe(AzureIoTSecurity_ListeningPortsV4_t *p, uint32_t v0, uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ flatbuffers_uint32_assign_to_pe(&p->local_address, v0); AzureIoTSecurity_ListeningPortsCommon_assign_to_pe(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_copy_to_pe(AzureIoTSecurity_ListeningPortsV4_t *p, const AzureIoTSecurity_ListeningPortsV4_t *p2)
{ flatbuffers_uint32_copy_to_pe(&p->local_address, &p2->local_address); AzureIoTSecurity_ListeningPortsCommon_copy_to_pe(&p->common, &p2->common);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_assign_from_pe(AzureIoTSecurity_ListeningPortsV4_t *p, uint32_t v0, uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ flatbuffers_uint32_assign_from_pe(&p->local_address, v0); AzureIoTSecurity_ListeningPortsCommon_assign_from_pe(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV4_t *AzureIoTSecurity_ListeningPortsV4_copy_from_pe(AzureIoTSecurity_ListeningPortsV4_t *p, const AzureIoTSecurity_ListeningPortsV4_t *p2)
{ flatbuffers_uint32_copy_from_pe(&p->local_address, &p2->local_address); AzureIoTSecurity_ListeningPortsCommon_copy_from_pe(&p->common, &p2->common);
  return p; }
__flatbuffers_build_struct(flatbuffers_, AzureIoTSecurity_ListeningPortsV4, 8, 4, AzureIoTSecurity_ListeningPortsV4_file_identifier, AzureIoTSecurity_ListeningPortsV4_type_identifier)
__flatbuffers_define_fixed_array_primitives(flatbuffers_, AzureIoTSecurity_ListeningPortsV4, AzureIoTSecurity_ListeningPortsV4_t)

#define __AzureIoTSecurity_ListeningPortsV6_formal_args , const uint32_t v0[4], uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2
#define __AzureIoTSecurity_ListeningPortsV6_call_args , v0, v1, v2
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_assign(AzureIoTSecurity_ListeningPortsV6_t *p, const uint32_t v0[4], uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ flatbuffers_uint32_array_copy(p->local_address, v0, 4); AzureIoTSecurity_ListeningPortsCommon_assign(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_copy(AzureIoTSecurity_ListeningPortsV6_t *p, const AzureIoTSecurity_ListeningPortsV6_t *p2)
{ flatbuffers_uint32_array_copy(p->local_address, p2->local_address, 4); AzureIoTSecurity_ListeningPortsCommon_copy(&p->common, &p2->common);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_assign_to_pe(AzureIoTSecurity_ListeningPortsV6_t *p, const uint32_t v0[4], uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ flatbuffers_uint32_array_copy_to_pe(p->local_address, v0, 4); AzureIoTSecurity_ListeningPortsCommon_assign_to_pe(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_copy_to_pe(AzureIoTSecurity_ListeningPortsV6_t *p, const AzureIoTSecurity_ListeningPortsV6_t *p2)
{ flatbuffers_uint32_array_copy_to_pe(p->local_address, p2->local_address, 4); AzureIoTSecurity_ListeningPortsCommon_copy_to_pe(&p->common, &p2->common);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_assign_from_pe(AzureIoTSecurity_ListeningPortsV6_t *p, const uint32_t v0[4], uint16_t v1, AzureIoTSecurity_Protocol_enum_t v2)
{ flatbuffers_uint32_array_copy_from_pe(p->local_address, v0, 4); AzureIoTSecurity_ListeningPortsCommon_assign_from_pe(&p->common, v1, v2);
  return p; }
static inline AzureIoTSecurity_ListeningPortsV6_t *AzureIoTSecurity_ListeningPortsV6_copy_from_pe(AzureIoTSecurity_ListeningPortsV6_t *p, const AzureIoTSecurity_ListeningPortsV6_t *p2)
{ flatbuffers_uint32_array_copy_from_pe(p->local_address, p2->local_address, 4); AzureIoTSecurity_ListeningPortsCommon_copy_from_pe(&p->common, &p2->common);
  return p; }
__flatbuffers_build_struct(flatbuffers_, AzureIoTSecurity_ListeningPortsV6, 20, 4, AzureIoTSecurity_ListeningPortsV6_file_identifier, AzureIoTSecurity_ListeningPortsV6_type_identifier)
__flatbuffers_define_fixed_array_primitives(flatbuffers_, AzureIoTSecurity_ListeningPortsV6, AzureIoTSecurity_ListeningPortsV6_t)

static const flatbuffers_voffset_t __AzureIoTSecurity_ListeningPorts_required[] = { 0 };
typedef flatbuffers_ref_t AzureIoTSecurity_ListeningPorts_ref_t;
static AzureIoTSecurity_ListeningPorts_ref_t AzureIoTSecurity_ListeningPorts_clone(flatbuffers_builder_t *B, AzureIoTSecurity_ListeningPorts_table_t t);
__flatbuffers_build_table(flatbuffers_, AzureIoTSecurity_ListeningPorts, 2)

#define __AzureIoTSecurity_ListeningPorts_formal_args , AzureIoTSecurity_ListeningPortsV4_vec_ref_t v0, AzureIoTSecurity_ListeningPortsV6_vec_ref_t v1
#define __AzureIoTSecurity_ListeningPorts_call_args , v0, v1
static inline AzureIoTSecurity_ListeningPorts_ref_t AzureIoTSecurity_ListeningPorts_create(flatbuffers_builder_t *B __AzureIoTSecurity_ListeningPorts_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, AzureIoTSecurity_ListeningPorts, AzureIoTSecurity_ListeningPorts_file_identifier, AzureIoTSecurity_ListeningPorts_type_identifier)

__flatbuffers_build_vector_field(0, flatbuffers_, AzureIoTSecurity_ListeningPorts_ipv4_ports, AzureIoTSecurity_ListeningPortsV4, AzureIoTSecurity_ListeningPortsV4_t, AzureIoTSecurity_ListeningPorts)
__flatbuffers_build_vector_field(1, flatbuffers_, AzureIoTSecurity_ListeningPorts_ipv6_ports, AzureIoTSecurity_ListeningPortsV6, AzureIoTSecurity_ListeningPortsV6_t, AzureIoTSecurity_ListeningPorts)

static inline AzureIoTSecurity_ListeningPorts_ref_t AzureIoTSecurity_ListeningPorts_create(flatbuffers_builder_t *B __AzureIoTSecurity_ListeningPorts_formal_args)
{
    if (AzureIoTSecurity_ListeningPorts_start(B)
        || AzureIoTSecurity_ListeningPorts_ipv4_ports_add(B, v0)
        || AzureIoTSecurity_ListeningPorts_ipv6_ports_add(B, v1)) {
        return 0;
    }
    return AzureIoTSecurity_ListeningPorts_end(B);
}

static AzureIoTSecurity_ListeningPorts_ref_t AzureIoTSecurity_ListeningPorts_clone(flatbuffers_builder_t *B, AzureIoTSecurity_ListeningPorts_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (AzureIoTSecurity_ListeningPorts_start(B)
        || AzureIoTSecurity_ListeningPorts_ipv4_ports_pick(B, t)
        || AzureIoTSecurity_ListeningPorts_ipv6_ports_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, AzureIoTSecurity_ListeningPorts_end(B));
}

#include "flatcc/flatcc_epilogue.h"
#endif /* LISTENING_PORTS_BUILDER_H */
