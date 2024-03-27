/**************************************************************************/
/*                                                                                                                              */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                                                                               */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                                                                               */
/**************************************************************************/

/**************************************************************************/
/* Copyright 2018-2022 NXP											      */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms. */
/* By expressly accepting such terms or by downloading, installing,       */
/* activating and/or otherwise using the software, you are agreeing that  */
/* you have read, and that you agree to comply with and are bound by,     */
/* such license terms.  If you do not agree to be bound by the applicable */
/* license terms, then you may not retain, install, activate or otherwise */
/* use the software                                                       */
/**************************************************************************/

#ifndef SAMPLE_CONFIG_H
#define SAMPLE_CONFIG_H

#ifdef __cplusplus
extern   "C" {
#endif

#if defined IOTC_DEVICE_MG
#include "EVSE_config_mg.h"
#elif defined IOTC_DEVICE_PY
#include "EVSE_config_py.h"
#endif


#ifdef __cplusplus
}
#endif
#endif /* SAMPLE_CONFIG_H */
