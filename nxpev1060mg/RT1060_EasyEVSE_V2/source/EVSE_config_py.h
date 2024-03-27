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

#ifndef SAMPLE_CONFIG_PY_H
#define SAMPLE_CONFIG_PY_H

#ifdef __cplusplus
extern   "C" {
#endif

/*
 * IoT-Connect config for conditionals in EVSE_iot_comms.c
 */
#define DISABLE_FOR_IOTCONNECT				// Disables setup of the shadow and command topics

/*************************************************************************************************/
/* This sample uses three different schemes to authenticate to IoT Central                                   */
/*  Set ONLY ONE authentication scheme with a 1 to select, the other two should be set to 0    */
/*************************************************************************************************/
#define EVSE_SAS_AUTH                    0   /*  Set to one to use  : symmetric keys  */
#define EVSE_X509_AUTH                   1  /*  Set to one to use  : certificate stored in i.MX RT106x Flash*/
#define EVSE_X509_SE050_AUTH     		 0  /*  Set to one to use  : certificate stored securely in SE050 Secure module */

#if    ( EVSE_SAS_AUTH == 1)
    #define USE_DEVICE_SYMMETRIC_KEY 1 /* do not modify */
/* after the device has been registered and  provisioned with DPS, */
/* the DEVICE_ID is the same than REGISTRATION ID                          */
    #define DEVICE_ID                                             "copy here your device ID"
    /* Paste the symmetric key value from the device connection prompt in the Azure Iot Central Application */
    #define DEVICE_SYMMETRIC_KEY                   				  "copy here your device symmetric key"
#elif ( EVSE_X509_AUTH == 1)
	#define USE_DEVICE_CERTIFICATE 1
/* after the device has been registered and  provisioned with DPS, */
/* the DEVICE_ID is the same than REGISTRATION ID                          */
#define DEVICE_ID                                        "pyevse"

#elif (EVSE_X509_SE050_AUTH == 1 )
   #define USE_SE05x_DEVICE_CERTIFICATE 1     /** do not modify this define*/
/* after the device has been registered and  provisioned with DPS, */
/* the DEVICE_ID is the same than REGISTRATION ID                          */
   #define DEVICE_ID                                        "copy here your device ID"

#endif /* Authentication scheme selection */

/*******************************************************************************************/
/* Set to 1  to contact DPS  service, 0 to connect to application  directly                              */
/* If this is the first time the device will be registered, you must set this define to 1,         */
/* After a successful registration , you may change it to zero , reducing subsequent        */
 /* device connection times                                                                                                            */
/******************************************************************************************/
#define EVSE_DPS                            0

#if (EVSE_DPS == 1)

    #define  ENABLE_DPS_SAMPLE 1    /** do not modify the ENDPOINT define */

	/*  Fixed DPS endpoint, we recommended to leave it as it is,  unless you have a private DPS endpoint */
	#define ENDPOINT                                    "global.azure-devices-provisioning.net"

   /* From the Azure Iot Central application paste your device ID_SCOPE */
	#define ID_SCOPE                                     "copy here your device ID scope"

/* Use the same registration ID that you used to register the device in the Azure Iot Central application
*  Please note that  for X509 enrollment registration ID  must match device certificate CN */
	#define REGISTRATION_ID                      DEVICE_ID


#elif( EVSE_DPS == 0)
/* Required when DPS is not used.  */
/******************************************************************************************/
 /* These values can be picked from device connection string which is of format :           */
 /* HostName=<host1>;DeviceId=<device1>;SharedAccessKey=<key1>                           */
 /* HOST_NAME can be set to <host1>,                                                                                      */
 /* DEVICE_ID can be set to <device1>,                                                                                       */
 /* DEVICE_SYMMETRIC_KEY can be set to <key1>.                                                                  */
/*  The Host name string  can be picked from the Log terminal                                            */
/******************************************************************************************/
#define HOST_NAME                                   "a3etk4e19usyja-ats.iot.us-east-1.amazonaws.com" /* Use with MyEasyEVSEDevice and 377808958120579818576399*/
#endif /* DPS selection */


/* Defined, telemetry is disabled. */
/*
#define DISABLE_TELEMETRY_SAMPLE
*/

/* Defined, C2D is disabled. */
/*
#define DISABLE_C2D_SAMPLE
*/

/* Defined, Direct method is disabled. */
/*
#define DISABLE_DIRECT_METHOD_SAMPLE
*/

/* Defined, Device twin is disabled. */
/*
#define DISABLE_DEVICE_TWIN_SAMPLE
*/

/* Optional module ID.  */
#ifndef MODULE_ID
#define MODULE_ID                                   ""
#endif /* MODULE_ID */


#ifdef USE_DEVICE_CERTIFICATE
/* Using X509 certificate authenticate to connect to IoT Central,
   set the device certificate as your device.  */

const unsigned char sample_device_cert_ptr[] = {
	0x30, 0x82, 0x03, 0x59, 0x30, 0x82, 0x02, 0x41, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x02, 0xba, 0x25, 0x21, 0xeb, 0x15, 0xba, 0x9e, 0x2a,
	0x17, 0xad, 0x92, 0xd9, 0x06, 0xd9, 0x6f, 0xcc, 0x01, 0xa7, 0x20, 0x30,
	0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	0x05, 0x00, 0x30, 0x4d, 0x31, 0x4b, 0x30, 0x49, 0x06, 0x03, 0x55, 0x04,
	0x0b, 0x0c, 0x42, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x20, 0x57, 0x65,
	0x62, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4f,
	0x3d, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x20,
	0x49, 0x6e, 0x63, 0x2e, 0x20, 0x4c, 0x3d, 0x53, 0x65, 0x61, 0x74, 0x74,
	0x6c, 0x65, 0x20, 0x53, 0x54, 0x3d, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e,
	0x67, 0x74, 0x6f, 0x6e, 0x20, 0x43, 0x3d, 0x55, 0x53, 0x30, 0x1e, 0x17,
	0x0d, 0x32, 0x34, 0x30, 0x33, 0x32, 0x35, 0x32, 0x33, 0x30, 0x34, 0x31,
	0x31, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
	0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x41, 0x57, 0x53, 0x20, 0x49, 0x6f,
	0x54, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
	0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
	0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf6, 0xfd,
	0x42, 0xd7, 0x78, 0x86, 0x27, 0x19, 0xdd, 0xde, 0xca, 0xd6, 0x60, 0x9c,
	0x89, 0x08, 0x90, 0x16, 0x88, 0x1b, 0x19, 0xaf, 0x5a, 0xab, 0x75, 0xbc,
	0x2c, 0x21, 0x21, 0x64, 0x6f, 0x17, 0xb6, 0x89, 0x63, 0xa4, 0x4a, 0x26,
	0xb5, 0x83, 0x47, 0x23, 0x30, 0xd3, 0x86, 0xc9, 0xdf, 0x60, 0x2b, 0x5b,
	0x7e, 0xf9, 0x4c, 0x18, 0xdb, 0x3b, 0x78, 0xaa, 0x58, 0x24, 0x8c, 0x0e,
	0x08, 0x68, 0xe5, 0x98, 0x26, 0x6b, 0x90, 0x9c, 0x54, 0x48, 0xca, 0xc2,
	0x08, 0x9f, 0xe7, 0xe1, 0x51, 0x43, 0x58, 0xb0, 0x72, 0x12, 0x67, 0xc0,
	0xbc, 0xff, 0xe6, 0x92, 0x01, 0x94, 0xb7, 0x49, 0x25, 0x73, 0xe6, 0x33,
	0xb7, 0x4c, 0x64, 0xbb, 0x98, 0x17, 0xbb, 0x4f, 0xb6, 0x3a, 0x4b, 0x36,
	0xea, 0x51, 0x10, 0x08, 0x82, 0xfc, 0xa1, 0xaa, 0x02, 0x2e, 0x7a, 0x49,
	0x8c, 0x2a, 0xed, 0xd6, 0x4c, 0x82, 0xd5, 0x81, 0x9c, 0xd0, 0xc3, 0x14,
	0x8d, 0x9e, 0x76, 0x96, 0xd8, 0xa2, 0x0d, 0xba, 0x45, 0x87, 0xb7, 0x04,
	0x54, 0x49, 0x58, 0x51, 0x89, 0x1e, 0x6a, 0xd0, 0x74, 0x8d, 0x2a, 0x3f,
	0xeb, 0xc9, 0xad, 0x5a, 0xe3, 0xb9, 0x58, 0x57, 0xb3, 0xaa, 0x95, 0xe1,
	0xad, 0x62, 0x5f, 0x67, 0x95, 0xe3, 0x70, 0x7d, 0xfd, 0x9c, 0x14, 0x57,
	0x9e, 0x4a, 0xfd, 0x81, 0xb2, 0x4e, 0x60, 0x80, 0x84, 0x5c, 0x3b, 0x6e,
	0xc5, 0xf7, 0xb2, 0x19, 0xd1, 0x83, 0x06, 0x5a, 0xca, 0x8d, 0xfb, 0xf5,
	0x65, 0xe9, 0xe4, 0xa3, 0x08, 0x30, 0xf5, 0xd2, 0x57, 0x70, 0xda, 0x20,
	0x17, 0x60, 0xd1, 0x63, 0xc7, 0x43, 0x72, 0x44, 0xec, 0x12, 0x93, 0xa9,
	0x04, 0x9e, 0xc5, 0x04, 0x40, 0x4e, 0x5b, 0xe8, 0x6a, 0xa1, 0x7a, 0x12,
	0x0b, 0x87, 0xcb, 0x89, 0x61, 0x4b, 0x47, 0x3e, 0x41, 0xb8, 0x20, 0x39,
	0x7d, 0x6d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x60, 0x30, 0x5e, 0x30,
	0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
	0xc2, 0xad, 0x66, 0x98, 0xfb, 0x5b, 0x5e, 0x13, 0x6e, 0xac, 0xa6, 0xe8,
	0xd4, 0x62, 0x64, 0x4e, 0xff, 0xe4, 0xba, 0x50, 0x30, 0x1d, 0x06, 0x03,
	0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x61, 0xa7, 0x22, 0x98, 0x74,
	0x48, 0x40, 0x54, 0x96, 0x58, 0x8d, 0xb1, 0x37, 0x2c, 0xfb, 0x43, 0x58,
	0x9d, 0x90, 0x38, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
	0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
	0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
	0x03, 0x82, 0x01, 0x01, 0x00, 0x9a, 0xe1, 0x90, 0xfb, 0x18, 0x6e, 0xe7,
	0xb2, 0xe1, 0x9d, 0x50, 0x3d, 0xc9, 0xf3, 0xfd, 0x7a, 0x4a, 0x73, 0x30,
	0x6d, 0xb7, 0x59, 0x25, 0x56, 0xc8, 0x75, 0xb0, 0xfc, 0x1b, 0x33, 0x23,
	0xd8, 0x16, 0xdd, 0xd2, 0x0e, 0xf2, 0xfa, 0x26, 0x44, 0xb2, 0x84, 0xd0,
	0x56, 0x59, 0xd4, 0x7e, 0xd0, 0xc5, 0xba, 0xa4, 0x77, 0x16, 0x60, 0x22,
	0x32, 0x9a, 0xac, 0x6d, 0xbf, 0x0b, 0xe6, 0x2b, 0x6a, 0x4f, 0xa6, 0xc7,
	0x78, 0x10, 0xa2, 0x8a, 0x8f, 0x5f, 0x4b, 0xa8, 0xba, 0x55, 0x39, 0xa9,
	0x91, 0x8e, 0x34, 0xae, 0x7c, 0x0a, 0x12, 0x0e, 0x58, 0x91, 0xdd, 0x35,
	0x43, 0xa9, 0xf2, 0x1d, 0x03, 0xa5, 0xb8, 0xe5, 0x74, 0x63, 0x0d, 0x4a,
	0x28, 0x00, 0x00, 0x9c, 0x50, 0x10, 0xa9, 0xf7, 0x86, 0xc5, 0xfe, 0xad,
	0xe5, 0x3b, 0x59, 0x8e, 0x9a, 0x7e, 0xea, 0x93, 0xf7, 0xa3, 0x4b, 0x64,
	0x80, 0x84, 0x60, 0x37, 0x82, 0xf1, 0x14, 0x7d, 0x31, 0x48, 0xdb, 0xa1,
	0xb8, 0x5b, 0x29, 0xc8, 0xc4, 0x1f, 0x33, 0x4e, 0xde, 0x2a, 0xc1, 0xd2,
	0xb1, 0xf7, 0x40, 0xd1, 0x1e, 0x09, 0x53, 0xdc, 0x26, 0xa0, 0x8c, 0xdd,
	0xba, 0x85, 0x6c, 0x87, 0xfb, 0xcd, 0xa1, 0xc8, 0xee, 0xe9, 0x35, 0x8f,
	0xf9, 0xf8, 0x09, 0x85, 0xd7, 0x86, 0x02, 0x4f, 0x46, 0x6c, 0xef, 0x00,
	0x87, 0x95, 0x71, 0xb4, 0xd6, 0xfe, 0x57, 0x0c, 0x49, 0x62, 0x4f, 0x07,
	0x7d, 0xa2, 0x62, 0x25, 0x95, 0x66, 0xf8, 0xe8, 0xec, 0xbd, 0x9c, 0xcb,
	0x15, 0x00, 0xf4, 0x86, 0x59, 0x61, 0x57, 0xdf, 0x05, 0xba, 0x98, 0x06,
	0x92, 0xfc, 0x79, 0x9c, 0x1c, 0x72, 0x69, 0x4e, 0xc8, 0x99, 0xbd, 0xc3,
	0x67, 0x93, 0xee, 0xba, 0x39, 0xf2, 0x67, 0xf3, 0x70, 0x23, 0x60, 0x5f,
	0xcd, 0x57, 0x39, 0x6b, 0x60, 0x5e, 0xd2, 0xbc, 0x4f
};

int sample_device_cert_len = sizeof(sample_device_cert_ptr);

const unsigned char sample_device_private_key_ptr[] = {
	0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
	0xf6, 0xfd, 0x42, 0xd7, 0x78, 0x86, 0x27, 0x19, 0xdd, 0xde, 0xca, 0xd6,
	0x60, 0x9c, 0x89, 0x08, 0x90, 0x16, 0x88, 0x1b, 0x19, 0xaf, 0x5a, 0xab,
	0x75, 0xbc, 0x2c, 0x21, 0x21, 0x64, 0x6f, 0x17, 0xb6, 0x89, 0x63, 0xa4,
	0x4a, 0x26, 0xb5, 0x83, 0x47, 0x23, 0x30, 0xd3, 0x86, 0xc9, 0xdf, 0x60,
	0x2b, 0x5b, 0x7e, 0xf9, 0x4c, 0x18, 0xdb, 0x3b, 0x78, 0xaa, 0x58, 0x24,
	0x8c, 0x0e, 0x08, 0x68, 0xe5, 0x98, 0x26, 0x6b, 0x90, 0x9c, 0x54, 0x48,
	0xca, 0xc2, 0x08, 0x9f, 0xe7, 0xe1, 0x51, 0x43, 0x58, 0xb0, 0x72, 0x12,
	0x67, 0xc0, 0xbc, 0xff, 0xe6, 0x92, 0x01, 0x94, 0xb7, 0x49, 0x25, 0x73,
	0xe6, 0x33, 0xb7, 0x4c, 0x64, 0xbb, 0x98, 0x17, 0xbb, 0x4f, 0xb6, 0x3a,
	0x4b, 0x36, 0xea, 0x51, 0x10, 0x08, 0x82, 0xfc, 0xa1, 0xaa, 0x02, 0x2e,
	0x7a, 0x49, 0x8c, 0x2a, 0xed, 0xd6, 0x4c, 0x82, 0xd5, 0x81, 0x9c, 0xd0,
	0xc3, 0x14, 0x8d, 0x9e, 0x76, 0x96, 0xd8, 0xa2, 0x0d, 0xba, 0x45, 0x87,
	0xb7, 0x04, 0x54, 0x49, 0x58, 0x51, 0x89, 0x1e, 0x6a, 0xd0, 0x74, 0x8d,
	0x2a, 0x3f, 0xeb, 0xc9, 0xad, 0x5a, 0xe3, 0xb9, 0x58, 0x57, 0xb3, 0xaa,
	0x95, 0xe1, 0xad, 0x62, 0x5f, 0x67, 0x95, 0xe3, 0x70, 0x7d, 0xfd, 0x9c,
	0x14, 0x57, 0x9e, 0x4a, 0xfd, 0x81, 0xb2, 0x4e, 0x60, 0x80, 0x84, 0x5c,
	0x3b, 0x6e, 0xc5, 0xf7, 0xb2, 0x19, 0xd1, 0x83, 0x06, 0x5a, 0xca, 0x8d,
	0xfb, 0xf5, 0x65, 0xe9, 0xe4, 0xa3, 0x08, 0x30, 0xf5, 0xd2, 0x57, 0x70,
	0xda, 0x20, 0x17, 0x60, 0xd1, 0x63, 0xc7, 0x43, 0x72, 0x44, 0xec, 0x12,
	0x93, 0xa9, 0x04, 0x9e, 0xc5, 0x04, 0x40, 0x4e, 0x5b, 0xe8, 0x6a, 0xa1,
	0x7a, 0x12, 0x0b, 0x87, 0xcb, 0x89, 0x61, 0x4b, 0x47, 0x3e, 0x41, 0xb8,
	0x20, 0x39, 0x7d, 0x6d, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
	0x01, 0x00, 0x9e, 0xd5, 0xec, 0x40, 0x69, 0x4f, 0xcc, 0xa1, 0x83, 0xdf,
	0x9d, 0x0e, 0x14, 0x7f, 0x56, 0x58, 0xdd, 0x60, 0xc0, 0x12, 0xbd, 0x87,
	0xd9, 0x85, 0x5e, 0x67, 0xae, 0xf1, 0x77, 0x6a, 0x01, 0x4f, 0x7c, 0xa2,
	0x0a, 0x24, 0x43, 0x53, 0x75, 0x73, 0x81, 0x32, 0x0e, 0x5a, 0x59, 0xda,
	0x44, 0xfe, 0xb1, 0xa3, 0x5b, 0x9a, 0xb2, 0xe7, 0x61, 0x45, 0x73, 0xaa,
	0x08, 0x99, 0x28, 0x40, 0x76, 0x04, 0x0f, 0x72, 0xb3, 0x72, 0x85, 0x43,
	0x23, 0xa8, 0xd4, 0x4b, 0xc8, 0x04, 0x1d, 0xb8, 0xf6, 0xeb, 0x9a, 0x83,
	0x8e, 0x38, 0x6b, 0xe4, 0xb5, 0x26, 0xd4, 0x7e, 0x9c, 0xe9, 0xa8, 0x9d,
	0x2f, 0xaa, 0xc3, 0x26, 0x0b, 0x00, 0xe3, 0xdf, 0x08, 0x46, 0x6a, 0xbd,
	0x2e, 0x71, 0x7a, 0xa1, 0x4c, 0x3a, 0xe9, 0x56, 0xaf, 0xf6, 0x0b, 0x79,
	0x2b, 0x81, 0xfc, 0x3e, 0x84, 0x17, 0xaf, 0x70, 0x1b, 0x2e, 0xdc, 0xf5,
	0x77, 0xf1, 0xd1, 0x6b, 0xe3, 0x66, 0xfd, 0x32, 0xed, 0xde, 0x91, 0x22,
	0x14, 0x28, 0x62, 0xa9, 0xa9, 0xe4, 0x41, 0x44, 0x4e, 0xb0, 0x0d, 0x3e,
	0x86, 0xae, 0x7d, 0xc3, 0x2b, 0x41, 0x67, 0xed, 0xa6, 0x39, 0x68, 0x9c,
	0xba, 0xa2, 0x2d, 0x28, 0xcc, 0x32, 0xf1, 0x47, 0x81, 0xfa, 0xe1, 0x9c,
	0x75, 0xe0, 0x56, 0x5e, 0x1a, 0x65, 0x5c, 0x6f, 0x28, 0xf4, 0xc5, 0xfa,
	0x34, 0x58, 0x7c, 0xbc, 0x90, 0x46, 0x98, 0xc8, 0xf3, 0x8f, 0x09, 0xa5,
	0x7c, 0xa2, 0x15, 0x83, 0x9b, 0xc4, 0xed, 0xc0, 0x1b, 0x9a, 0x59, 0xa2,
	0xde, 0xf0, 0xc8, 0x01, 0x91, 0x00, 0x8b, 0x36, 0xd9, 0x21, 0x01, 0xc6,
	0x26, 0x69, 0x91, 0xba, 0x9c, 0x7b, 0xc6, 0xe3, 0x34, 0x8c, 0xcd, 0xc4,
	0x04, 0xd9, 0x10, 0x70, 0x6b, 0xfb, 0x78, 0xd1, 0x88, 0x67, 0xfb, 0x9e,
	0xe5, 0x2a, 0x68, 0xd0, 0xe8, 0x41, 0x02, 0x81, 0x81, 0x00, 0xfd, 0x70,
	0x1e, 0x91, 0x9d, 0x48, 0x87, 0x94, 0x0f, 0xc5, 0x7c, 0x3b, 0x49, 0xdc,
	0x40, 0x0f, 0x1b, 0x20, 0x76, 0x50, 0x01, 0xb4, 0x71, 0xe0, 0x68, 0x75,
	0xd2, 0x4b, 0x06, 0x2d, 0x85, 0x79, 0x44, 0x6b, 0x9f, 0x28, 0x32, 0x8e,
	0x18, 0x32, 0x7c, 0x46, 0xd0, 0x7d, 0x1a, 0x40, 0x69, 0xe1, 0xc8, 0x38,
	0xdf, 0x38, 0x73, 0x61, 0x00, 0x64, 0xaf, 0x85, 0xf1, 0xb8, 0x51, 0xf6,
	0x3f, 0xa6, 0x37, 0x64, 0x14, 0xdc, 0x5b, 0xcf, 0xeb, 0x31, 0x64, 0x5f,
	0xb5, 0xa8, 0xfe, 0x8f, 0x62, 0x56, 0xb9, 0x7e, 0xd3, 0xdb, 0xdf, 0x05,
	0x92, 0x65, 0xb4, 0x48, 0xcd, 0xf0, 0xaf, 0x73, 0x16, 0xf4, 0x26, 0x46,
	0x21, 0x2d, 0xd5, 0x96, 0x8c, 0x9d, 0x4d, 0xdb, 0x57, 0x80, 0x65, 0xe2,
	0xf1, 0xdf, 0xe4, 0x95, 0xe8, 0xed, 0xcd, 0xee, 0xd6, 0x17, 0xcb, 0xb1,
	0x2f, 0x72, 0xb2, 0x7e, 0xaf, 0x45, 0x02, 0x81, 0x81, 0x00, 0xf9, 0x7c,
	0x73, 0xf6, 0x20, 0xdd, 0xd7, 0x0e, 0xdb, 0x3c, 0x26, 0x52, 0x0b, 0xd7,
	0x7a, 0x4f, 0x65, 0xa8, 0xf8, 0x11, 0xa3, 0xd3, 0x10, 0xd3, 0x65, 0x87,
	0x60, 0x52, 0xda, 0xac, 0x9a, 0x73, 0x6d, 0x15, 0x3a, 0xed, 0x4f, 0xaf,
	0x9d, 0x58, 0xbc, 0x08, 0x81, 0x33, 0xc3, 0x5b, 0xc1, 0x06, 0xd2, 0xa2,
	0x8a, 0xb5, 0xd2, 0x83, 0x6c, 0x27, 0xe3, 0x51, 0x92, 0x3a, 0x96, 0x44,
	0x3b, 0x57, 0x2a, 0xf8, 0x73, 0x7e, 0xf8, 0x75, 0x56, 0xf8, 0x39, 0xf9,
	0xf9, 0x74, 0x47, 0x0b, 0x04, 0x0b, 0x9f, 0x0d, 0xbf, 0x09, 0xcc, 0x81,
	0x85, 0x1c, 0x04, 0x17, 0x4d, 0x50, 0x09, 0x1c, 0xe4, 0xe3, 0x64, 0x01,
	0x5d, 0xe9, 0xce, 0xb3, 0xb6, 0x0e, 0x7e, 0x01, 0x65, 0x02, 0x16, 0x54,
	0xa9, 0x92, 0xcb, 0x0f, 0xd1, 0x9f, 0x38, 0xbf, 0x55, 0x56, 0xb6, 0x5e,
	0x16, 0xde, 0x12, 0x4b, 0x44, 0x09, 0x02, 0x81, 0x81, 0x00, 0xe0, 0x31,
	0xe9, 0xe8, 0xd8, 0xa1, 0x4b, 0xc6, 0x6f, 0xf9, 0x3c, 0x7f, 0xda, 0x43,
	0xeb, 0xab, 0x31, 0x4d, 0x13, 0x3c, 0x8d, 0x75, 0x89, 0xf3, 0x81, 0x95,
	0x10, 0xd5, 0xeb, 0x7e, 0x23, 0x7f, 0xf6, 0x45, 0xda, 0x42, 0x9e, 0x0e,
	0x53, 0x5b, 0x7d, 0xd2, 0xcb, 0x26, 0x90, 0x2d, 0x81, 0x3d, 0x09, 0x79,
	0x3e, 0x06, 0x5b, 0x12, 0xe9, 0x5d, 0x28, 0x64, 0xae, 0x43, 0x66, 0xc6,
	0x16, 0xe2, 0x3c, 0x47, 0xdd, 0xa8, 0x5d, 0xd3, 0xdd, 0x74, 0x11, 0x1e,
	0x15, 0xbe, 0x8c, 0x8a, 0x5c, 0xec, 0xe9, 0x25, 0x47, 0xd7, 0x4e, 0x40,
	0x48, 0x94, 0x8d, 0xda, 0x85, 0xcb, 0xaf, 0xf9, 0x78, 0xc9, 0xbc, 0x7d,
	0xf7, 0x65, 0xeb, 0x77, 0x45, 0xa6, 0xf6, 0x33, 0xde, 0x01, 0x28, 0xa0,
	0x8d, 0x65, 0x89, 0x7a, 0x0f, 0xd7, 0x26, 0x80, 0x6c, 0x86, 0x1a, 0x5c,
	0x00, 0xe4, 0x4f, 0x00, 0x80, 0x9d, 0x02, 0x81, 0x81, 0x00, 0xb3, 0xb2,
	0x34, 0x43, 0xff, 0x80, 0x49, 0xba, 0x65, 0xa6, 0x79, 0x63, 0x77, 0x2c,
	0x08, 0xe8, 0xcf, 0x2c, 0x59, 0x21, 0x3b, 0x82, 0x77, 0x08, 0x0c, 0x84,
	0xe9, 0x98, 0x43, 0xf1, 0x36, 0x7e, 0x14, 0xff, 0xc9, 0xa5, 0xcc, 0x53,
	0x8d, 0x5d, 0xb0, 0x71, 0xdf, 0xbd, 0xcc, 0xe4, 0x75, 0xaf, 0xd8, 0x5f,
	0x42, 0xd1, 0x9b, 0x83, 0x15, 0x8f, 0xd5, 0x67, 0x97, 0x8f, 0xa3, 0x54,
	0x19, 0xf9, 0xba, 0xf5, 0xa1, 0x1a, 0xbf, 0x12, 0xa5, 0x45, 0xbd, 0x5c,
	0x93, 0x94, 0x70, 0xe7, 0x3a, 0x4e, 0xb4, 0x8d, 0x4e, 0x20, 0x5c, 0xb0,
	0x9d, 0x93, 0x84, 0x4e, 0xd4, 0x5c, 0xe5, 0x73, 0x6e, 0x59, 0x6a, 0x5a,
	0xa1, 0xae, 0x1a, 0x37, 0xce, 0xd5, 0xb9, 0x64, 0x7f, 0xc0, 0x75, 0x1d,
	0x1d, 0xd6, 0xa1, 0x74, 0x0f, 0x64, 0x43, 0x97, 0x6c, 0x7c, 0x3c, 0x76,
	0xa0, 0xb9, 0xeb, 0x2b, 0x53, 0x21, 0x02, 0x81, 0x80, 0x3b, 0x9c, 0xc9,
	0x01, 0x50, 0x64, 0xcc, 0xe6, 0x50, 0xe6, 0x38, 0xf7, 0xf8, 0x8d, 0xef,
	0xf0, 0x2a, 0x53, 0xce, 0x5a, 0xeb, 0x78, 0x03, 0x66, 0x6d, 0x86, 0x00,
	0xef, 0xe8, 0x47, 0x52, 0xab, 0x93, 0xa3, 0xc2, 0x55, 0x56, 0xca, 0xeb,
	0x53, 0x66, 0x33, 0xd1, 0x43, 0x49, 0x40, 0xc7, 0xc6, 0xfa, 0xd3, 0xc0,
	0x8c, 0xf3, 0x0a, 0x3d, 0x25, 0x52, 0xb5, 0xa3, 0xa2, 0xb3, 0x1f, 0xb2,
	0x7b, 0x75, 0xaf, 0xd8, 0x9b, 0x71, 0x47, 0x4c, 0x5f, 0xfa, 0xe7, 0x72,
	0xb1, 0xea, 0xf3, 0xa7, 0x58, 0x9c, 0x8a, 0x7c, 0x7f, 0x98, 0xa4, 0xd0,
	0xe6, 0xec, 0x00, 0xcc, 0x3e, 0x66, 0x77, 0xc5, 0x22, 0x4b, 0x40, 0x0c,
	0xd1, 0x90, 0xbd, 0xe8, 0x5c, 0x39, 0x55, 0x5b, 0x4f, 0xb2, 0x30, 0xea,
	0xf3, 0x33, 0xb6, 0x00, 0xfe, 0x34, 0x3c, 0x60, 0xd0, 0xb7, 0xb2, 0x85,
	0x4a, 0xd8, 0x4b, 0xe2, 0x24
};

int sample_device_private_key_len = sizeof(sample_device_private_key_ptr);

/* Device Key type. */
#ifndef DEVICE_KEY_TYPE
 #define DEVICE_KEY_TYPE                             NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER /* Use for RSA cert and keys */
#endif /* DEVICE_KEY_TYPE */

#endif /* USE_DEVICE_CERTIFICATE */

#ifdef USE_SE05x_DEVICE_CERTIFICATE
/* The X.509 certificate is retrieved from the EdgeLock SE05x secure element

   The EC private key is stored securely inside the EdgeLock SE05x secure element.
   The TLS client authentication is performed by the EdgeLock SE05x secure element.
*/

/* The EC dummy private key ANS.1 coding: */
/*SEQ(30) LEN=0x77{
    INT(02) LEN=0x1 VAL=01
    OCTET STRING(04) LEN=0x20 VAL=00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    SEQ(A0) LEN=0xA{
        OID(06) LEN=0x8 VAL=UNIVERSAL OID.1.2.840.10045.3.1.7
    };
    SEQ(A1) LEN=0x44{
        BIT STRING(03) LEN=0x42 VAL=00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    };
}; */

/* Dummy Private-Key: NIST CURVE: P-256 */
const unsigned char dummy_device_private_key_ptr[] = {
		0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int dummy_device_private_key_len = sizeof(dummy_device_private_key_ptr);

/* Device Key type. */
#ifndef DEVICE_KEY_TYPE
#define DEVICE_KEY_TYPE                             NX_SECURE_X509_KEY_TYPE_EC_DER
#endif /* DEVICE_KEY_TYPE */

#endif /* USE_SE05x_DEVICE_CERTIFICATE */


/* Define the Azure RTOS IOT thread stack and priority.  */
#ifndef NX_AZURE_IOT_STACK_SIZE
 #define NX_AZURE_IOT_STACK_SIZE                   (2048)
#endif /* NX_AZURE_IOT_STACK_SIZE */

#ifndef NX_AZURE_IOT_THREAD_PRIORITY
 #define NX_AZURE_IOT_THREAD_PRIORITY     (4)
#endif /* NX_AZURE_IOT_THREAD_PRIORITY */

#ifndef SAMPLE_MAX_BUFFER
 #define SAMPLE_MAX_BUFFER                           (256)
#endif /* SAMPLE_MAX_BUFFER */

/* Define the sample thread stack and priority.  */
#ifndef SAMPLE_STACK_SIZE
 #define SAMPLE_STACK_SIZE                              (2048)
#endif /* SAMPLE_STACK_SIZE */

#ifndef SAMPLE_THREAD_PRIORITY
 #define SAMPLE_THREAD_PRIORITY                  (16)
#endif /* SAMPLE_THREAD_PRIORITY */

/* Define sample properties count. */
#define MAX_PROPERTY_COUNT                          2

/** CONFIG ERROR CHECKER **/
#if    ( (EVSE_SAS_AUTH  == 0) &&  (EVSE_X509_AUTH == 0)  && (EVSE_X509_SE050_AUTH ==0) ||  (EVSE_SAS_AUTH + EVSE_X509_AUTH + EVSE_X509_SE050_AUTH  )>1)

CONFIG  ERROR > NO AUTH METHOD SELECTED
CONFIG ERROR  > POSSIBLY MORE THAN ONE AUTH METHOD WAS SELECTED
#endif


#ifdef __cplusplus
}
#endif
#endif /* SAMPLE_CONFIG_PY_H */