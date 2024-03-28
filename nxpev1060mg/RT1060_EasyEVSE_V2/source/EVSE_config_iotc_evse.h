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

#ifndef SAMPLE_CONFIG_MG_H
#define SAMPLE_CONFIG_MG_H

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
   #define DEVICE_ID                                        "iotc-evse"

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
	0x30, 0x82, 0x03, 0x5a, 0x30, 0x82, 0x02, 0x42, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x15, 0x00, 0xe6, 0x4f, 0x0b, 0xff, 0xf7, 0x82, 0x20, 0x85,
	0x65, 0x8b, 0xf4, 0xac, 0x5d, 0x5c, 0x87, 0xa5, 0x58, 0xb2, 0xf4, 0x6a,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x0b, 0x05, 0x00, 0x30, 0x4d, 0x31, 0x4b, 0x30, 0x49, 0x06, 0x03, 0x55,
	0x04, 0x0b, 0x0c, 0x42, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x20, 0x57,
	0x65, 0x62, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20,
	0x4f, 0x3d, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
	0x20, 0x49, 0x6e, 0x63, 0x2e, 0x20, 0x4c, 0x3d, 0x53, 0x65, 0x61, 0x74,
	0x74, 0x6c, 0x65, 0x20, 0x53, 0x54, 0x3d, 0x57, 0x61, 0x73, 0x68, 0x69,
	0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x20, 0x43, 0x3d, 0x55, 0x53, 0x30, 0x1e,
	0x17, 0x0d, 0x32, 0x34, 0x30, 0x33, 0x32, 0x38, 0x31, 0x31, 0x35, 0x38,
	0x31, 0x33, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
	0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x41, 0x57, 0x53, 0x20, 0x49,
	0x6f, 0x54, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
	0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdc,
	0x79, 0x8d, 0x46, 0x15, 0x87, 0x31, 0x8d, 0x9a, 0xe3, 0x16, 0x72, 0x97,
	0x13, 0xa4, 0xe6, 0xc0, 0x73, 0xd9, 0x23, 0x15, 0x63, 0xed, 0x17, 0xd6,
	0x49, 0x25, 0x62, 0x06, 0xbc, 0x9a, 0x83, 0x96, 0x66, 0xe3, 0xa0, 0xfe,
	0x40, 0x39, 0x3a, 0xc2, 0x09, 0xd9, 0x55, 0x73, 0x9d, 0xc9, 0x66, 0x57,
	0xbf, 0xee, 0x5d, 0x6b, 0x19, 0xb7, 0xa6, 0xf2, 0x53, 0xd6, 0x02, 0xf6,
	0x62, 0x32, 0x82, 0x5c, 0xbd, 0x35, 0xbf, 0x15, 0x51, 0x1c, 0xdb, 0x90,
	0x36, 0xb6, 0xc6, 0x15, 0xe2, 0xf9, 0x3f, 0xeb, 0x35, 0xe9, 0x76, 0xda,
	0xd9, 0x98, 0xa9, 0x2e, 0x37, 0x8f, 0x5a, 0xc5, 0x19, 0xd8, 0x07, 0x56,
	0x15, 0x05, 0xe0, 0x56, 0xb7, 0x2f, 0xbd, 0x9d, 0x0b, 0x54, 0x08, 0x39,
	0x29, 0x90, 0x4e, 0x3a, 0x88, 0xa3, 0xc4, 0x2d, 0xb4, 0x66, 0x3e, 0xa3,
	0x57, 0x71, 0x87, 0x1b, 0xab, 0x32, 0xfe, 0x7b, 0xb2, 0x4c, 0x77, 0xce,
	0x51, 0x3c, 0xdf, 0x0c, 0x9a, 0x88, 0xf1, 0x33, 0x74, 0xc6, 0x72, 0x46,
	0x51, 0x79, 0x24, 0x08, 0xf5, 0xf1, 0x36, 0x49, 0xeb, 0xc7, 0x3a, 0x61,
	0xbd, 0x3c, 0x62, 0x5f, 0x1e, 0x1a, 0x8a, 0x89, 0x47, 0xb6, 0x0e, 0xad,
	0xf4, 0x0f, 0x43, 0xf0, 0xcb, 0x38, 0x14, 0x95, 0x17, 0x42, 0x3b, 0x50,
	0xb1, 0xb4, 0x61, 0xe1, 0xc6, 0xad, 0x92, 0x23, 0xf5, 0x35, 0x6a, 0xcb,
	0xa3, 0x4f, 0xef, 0xbe, 0x7a, 0x33, 0x6c, 0xc4, 0x8c, 0xcc, 0x6d, 0xdf,
	0xc0, 0xd7, 0xe7, 0xfe, 0xfb, 0xff, 0xe9, 0x49, 0xee, 0x99, 0xdb, 0xfd,
	0x60, 0xa6, 0xef, 0x1d, 0xbe, 0xbc, 0xc4, 0x53, 0x27, 0xad, 0x32, 0x80,
	0x43, 0x10, 0x1e, 0x05, 0x40, 0x25, 0xaf, 0x8c, 0xa1, 0x22, 0x3d, 0xae,
	0x73, 0xa5, 0x5c, 0x52, 0x12, 0x61, 0x4d, 0x27, 0xa0, 0x3c, 0x3d, 0xc1,
	0xad, 0x81, 0x4d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x60, 0x30, 0x5e,
	0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
	0x14, 0x76, 0x60, 0x46, 0x96, 0x03, 0xc2, 0x20, 0xe8, 0x4b, 0xd9, 0xc3,
	0x3a, 0x55, 0xb5, 0x36, 0x6c, 0xca, 0x82, 0xf1, 0xbb, 0x30, 0x1d, 0x06,
	0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x31, 0x7f, 0xa2, 0xc0,
	0x01, 0xc4, 0xf9, 0x68, 0xb2, 0xc8, 0xd9, 0x93, 0x71, 0xa8, 0x78, 0x56,
	0x61, 0x3c, 0x3a, 0xda, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
	0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
	0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0d,
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
	0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x36, 0xe6, 0xba, 0x71, 0x8d, 0x0e,
	0xdd, 0xc4, 0xc1, 0xbb, 0xed, 0x69, 0xd9, 0x59, 0xf5, 0x2f, 0xb9, 0x61,
	0x35, 0xb5, 0xda, 0xaf, 0x07, 0xa8, 0x64, 0xb0, 0x6d, 0x7d, 0xef, 0x65,
	0x5c, 0x63, 0x81, 0x37, 0x00, 0xf3, 0xf1, 0xc6, 0xc3, 0xea, 0x8f, 0xad,
	0x7f, 0x94, 0xbd, 0xa8, 0xd3, 0x28, 0xce, 0x48, 0x2f, 0x5b, 0xaf, 0x01,
	0xea, 0x02, 0xa4, 0xd0, 0x53, 0x4b, 0x08, 0x05, 0x98, 0x4e, 0x9c, 0x2d,
	0xfe, 0x9d, 0x85, 0x08, 0xf6, 0x07, 0xcf, 0xc7, 0xb8, 0x29, 0xd0, 0x6d,
	0xa5, 0xc4, 0x4a, 0xec, 0x1a, 0xf2, 0xc9, 0x70, 0x7d, 0xe0, 0x95, 0x63,
	0xb3, 0x4c, 0x16, 0x9d, 0x7e, 0x75, 0x7d, 0xb9, 0xd3, 0xaa, 0x3c, 0xcd,
	0x50, 0xb8, 0xfa, 0x09, 0xde, 0xcc, 0x3e, 0x3c, 0x34, 0x0e, 0x46, 0xf4,
	0x2b, 0x06, 0xf7, 0x7d, 0x52, 0x48, 0x9a, 0xa7, 0x65, 0x66, 0x95, 0x1e,
	0xbd, 0xfc, 0x7a, 0xcf, 0x4a, 0x31, 0xe4, 0x07, 0xea, 0x65, 0x51, 0x47,
	0x36, 0xae, 0x69, 0x60, 0xe9, 0xde, 0x90, 0x42, 0x65, 0xd7, 0xed, 0x9d,
	0x14, 0xf6, 0x8f, 0x7a, 0x5f, 0x00, 0xb7, 0x42, 0x7b, 0x28, 0x5f, 0xc3,
	0x0b, 0xc9, 0x6a, 0x4d, 0x86, 0x57, 0x67, 0x34, 0xa8, 0x58, 0x04, 0x3a,
	0x8a, 0xad, 0xe0, 0x1a, 0xe0, 0xb0, 0x60, 0x39, 0x51, 0x4a, 0xa4, 0xba,
	0x2d, 0x12, 0x8e, 0xc5, 0xb3, 0x69, 0xd5, 0xe7, 0x48, 0xaa, 0xc9, 0x72,
	0xb0, 0x5e, 0x54, 0xfb, 0x5d, 0x4a, 0x48, 0x92, 0xd6, 0xf4, 0xf6, 0x4c,
	0x4b, 0x3e, 0x90, 0x1c, 0xd1, 0xcc, 0x68, 0x32, 0xad, 0x67, 0x1b, 0xe1,
	0x03, 0x00, 0x08, 0x34, 0x72, 0xce, 0xd6, 0x27, 0xd5, 0xf1, 0x56, 0xe5,
	0x22, 0x62, 0xdb, 0x39, 0x4f, 0x8f, 0x3e, 0xfa, 0x3a, 0x8e, 0x8f, 0x92,
	0x24, 0xc1, 0x85, 0xf8, 0xd7, 0x8e, 0x73, 0xcd, 0x5b, 0xa3
};

int sample_device_cert_len = sizeof(sample_device_cert_ptr);

const unsigned char sample_device_private_key_ptr[] = {
	0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
	0xdc, 0x79, 0x8d, 0x46, 0x15, 0x87, 0x31, 0x8d, 0x9a, 0xe3, 0x16, 0x72,
	0x97, 0x13, 0xa4, 0xe6, 0xc0, 0x73, 0xd9, 0x23, 0x15, 0x63, 0xed, 0x17,
	0xd6, 0x49, 0x25, 0x62, 0x06, 0xbc, 0x9a, 0x83, 0x96, 0x66, 0xe3, 0xa0,
	0xfe, 0x40, 0x39, 0x3a, 0xc2, 0x09, 0xd9, 0x55, 0x73, 0x9d, 0xc9, 0x66,
	0x57, 0xbf, 0xee, 0x5d, 0x6b, 0x19, 0xb7, 0xa6, 0xf2, 0x53, 0xd6, 0x02,
	0xf6, 0x62, 0x32, 0x82, 0x5c, 0xbd, 0x35, 0xbf, 0x15, 0x51, 0x1c, 0xdb,
	0x90, 0x36, 0xb6, 0xc6, 0x15, 0xe2, 0xf9, 0x3f, 0xeb, 0x35, 0xe9, 0x76,
	0xda, 0xd9, 0x98, 0xa9, 0x2e, 0x37, 0x8f, 0x5a, 0xc5, 0x19, 0xd8, 0x07,
	0x56, 0x15, 0x05, 0xe0, 0x56, 0xb7, 0x2f, 0xbd, 0x9d, 0x0b, 0x54, 0x08,
	0x39, 0x29, 0x90, 0x4e, 0x3a, 0x88, 0xa3, 0xc4, 0x2d, 0xb4, 0x66, 0x3e,
	0xa3, 0x57, 0x71, 0x87, 0x1b, 0xab, 0x32, 0xfe, 0x7b, 0xb2, 0x4c, 0x77,
	0xce, 0x51, 0x3c, 0xdf, 0x0c, 0x9a, 0x88, 0xf1, 0x33, 0x74, 0xc6, 0x72,
	0x46, 0x51, 0x79, 0x24, 0x08, 0xf5, 0xf1, 0x36, 0x49, 0xeb, 0xc7, 0x3a,
	0x61, 0xbd, 0x3c, 0x62, 0x5f, 0x1e, 0x1a, 0x8a, 0x89, 0x47, 0xb6, 0x0e,
	0xad, 0xf4, 0x0f, 0x43, 0xf0, 0xcb, 0x38, 0x14, 0x95, 0x17, 0x42, 0x3b,
	0x50, 0xb1, 0xb4, 0x61, 0xe1, 0xc6, 0xad, 0x92, 0x23, 0xf5, 0x35, 0x6a,
	0xcb, 0xa3, 0x4f, 0xef, 0xbe, 0x7a, 0x33, 0x6c, 0xc4, 0x8c, 0xcc, 0x6d,
	0xdf, 0xc0, 0xd7, 0xe7, 0xfe, 0xfb, 0xff, 0xe9, 0x49, 0xee, 0x99, 0xdb,
	0xfd, 0x60, 0xa6, 0xef, 0x1d, 0xbe, 0xbc, 0xc4, 0x53, 0x27, 0xad, 0x32,
	0x80, 0x43, 0x10, 0x1e, 0x05, 0x40, 0x25, 0xaf, 0x8c, 0xa1, 0x22, 0x3d,
	0xae, 0x73, 0xa5, 0x5c, 0x52, 0x12, 0x61, 0x4d, 0x27, 0xa0, 0x3c, 0x3d,
	0xc1, 0xad, 0x81, 0x4d, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
	0x01, 0x00, 0xaf, 0x2e, 0xfe, 0x2c, 0x13, 0xeb, 0x0a, 0x5a, 0xc4, 0x19,
	0x70, 0xba, 0xb8, 0x84, 0x69, 0x60, 0xd8, 0xc6, 0xb4, 0x60, 0x06, 0x1d,
	0x12, 0x45, 0x00, 0x85, 0xba, 0x68, 0x7b, 0x85, 0xdd, 0x18, 0x75, 0xa7,
	0x67, 0x73, 0x82, 0xd2, 0xb1, 0x26, 0x99, 0x0b, 0x8e, 0x5f, 0x31, 0xb0,
	0xcc, 0x58, 0xbf, 0x9c, 0xc7, 0xdf, 0xfe, 0xbb, 0xbe, 0x8b, 0xae, 0xbd,
	0x22, 0xad, 0xd3, 0xec, 0x0e, 0xca, 0x3a, 0xba, 0x35, 0x3c, 0x91, 0xc9,
	0x93, 0xae, 0x7a, 0x96, 0x9f, 0x00, 0x22, 0x5f, 0xe9, 0x40, 0xfa, 0xba,
	0x29, 0xb9, 0xc1, 0x07, 0x69, 0x1f, 0xf4, 0x93, 0x3d, 0x1b, 0x18, 0xc6,
	0x02, 0x3b, 0x42, 0x11, 0x0e, 0x4c, 0x45, 0x5a, 0xe5, 0x5a, 0x3a, 0xb0,
	0xc7, 0xa2, 0x89, 0x19, 0x17, 0x8a, 0xb1, 0x43, 0xe5, 0x2c, 0x7a, 0x4c,
	0x7f, 0x79, 0x81, 0xfc, 0x77, 0x3e, 0xad, 0xa3, 0x88, 0xad, 0xe7, 0x17,
	0x64, 0xb1, 0x01, 0xe1, 0x6e, 0x3c, 0xf8, 0x40, 0x56, 0x66, 0xe3, 0x40,
	0xdb, 0x01, 0x3e, 0xcc, 0xfa, 0xdd, 0x98, 0xb8, 0xab, 0xa4, 0x39, 0x1a,
	0xa7, 0x98, 0xc3, 0x6b, 0x88, 0x0c, 0xbd, 0x85, 0xdf, 0x58, 0xc1, 0xc4,
	0xed, 0x00, 0x5f, 0xd0, 0xfd, 0x80, 0x59, 0x0d, 0xa2, 0xb8, 0x32, 0x13,
	0x7b, 0xd2, 0x35, 0xa8, 0x8c, 0xcd, 0x82, 0x0c, 0xeb, 0xc8, 0x41, 0xdc,
	0x64, 0x9e, 0xf5, 0x62, 0x7b, 0x02, 0x3c, 0x83, 0xf8, 0x35, 0xad, 0x9c,
	0xc2, 0xf4, 0x66, 0x49, 0x34, 0x8c, 0x4c, 0xae, 0xe0, 0x72, 0x46, 0x32,
	0x3f, 0x6a, 0x3c, 0x58, 0xce, 0x16, 0x81, 0xd5, 0x2c, 0x19, 0xaf, 0x84,
	0x33, 0xcf, 0xfc, 0x1d, 0x89, 0x07, 0x4d, 0x80, 0x02, 0x49, 0x2e, 0x4b,
	0x6d, 0xa7, 0xb2, 0xf4, 0xac, 0xc2, 0xef, 0xbc, 0x56, 0x64, 0x23, 0x62,
	0xdb, 0x28, 0xfb, 0xa4, 0x0a, 0x01, 0x02, 0x81, 0x81, 0x00, 0xf4, 0x2f,
	0x2e, 0xd5, 0xd0, 0xda, 0x55, 0x09, 0x48, 0xe8, 0x09, 0x4e, 0x42, 0x37,
	0x19, 0xc9, 0x72, 0x81, 0xa5, 0xb4, 0x39, 0x21, 0x0d, 0x7a, 0x84, 0x45,
	0x09, 0x60, 0xab, 0xe3, 0xe7, 0xa1, 0x2d, 0x09, 0x15, 0xd7, 0xb2, 0xda,
	0x04, 0xe6, 0xa3, 0x7d, 0x79, 0xb5, 0xc3, 0x0e, 0x88, 0x69, 0xd1, 0x17,
	0x0b, 0x0f, 0x73, 0x9b, 0x5e, 0xaf, 0x43, 0xe2, 0x96, 0xaf, 0x1a, 0x01,
	0x24, 0x5e, 0xb0, 0x2e, 0xf2, 0xaa, 0x83, 0x46, 0x35, 0x48, 0x05, 0xd0,
	0xe9, 0x39, 0x11, 0xaa, 0xba, 0xc3, 0x81, 0x20, 0xee, 0x0b, 0xc9, 0x0d,
	0x99, 0xe7, 0x85, 0xbf, 0x4e, 0x24, 0x36, 0x91, 0x88, 0x9f, 0xc5, 0x8d,
	0xd6, 0xde, 0xaf, 0x1e, 0x93, 0xc4, 0x13, 0x68, 0xf8, 0x3e, 0xe1, 0x0d,
	0x50, 0x72, 0x09, 0x39, 0xe4, 0xb7, 0x4b, 0x25, 0xb6, 0x12, 0xeb, 0x1c,
	0xb6, 0xa3, 0x82, 0x75, 0xd1, 0x8d, 0x02, 0x81, 0x81, 0x00, 0xe7, 0x24,
	0xab, 0x48, 0x63, 0x04, 0xca, 0xfe, 0xcd, 0x2d, 0xca, 0x69, 0xf4, 0xf2,
	0xeb, 0x54, 0x45, 0x91, 0x9e, 0x96, 0x08, 0x0f, 0x77, 0xc3, 0x1a, 0x6b,
	0x7f, 0xd7, 0x83, 0x45, 0x57, 0x08, 0xce, 0x2c, 0xab, 0x96, 0x2b, 0xdf,
	0x1c, 0xaf, 0x33, 0x17, 0xc4, 0x24, 0xb7, 0x56, 0x97, 0x13, 0xe0, 0x9a,
	0xab, 0x61, 0x11, 0x69, 0x07, 0xe2, 0xbd, 0xb2, 0x27, 0x15, 0xa0, 0x8a,
	0x21, 0xec, 0x27, 0x16, 0xb8, 0x8c, 0x77, 0xb5, 0x8e, 0xb2, 0x9d, 0x3b,
	0xcd, 0x19, 0x0d, 0x74, 0xe4, 0x4b, 0xa0, 0x9d, 0xd1, 0xd7, 0xa6, 0x6f,
	0x69, 0x28, 0x1d, 0xe8, 0x1b, 0x55, 0xca, 0xe4, 0x1a, 0x15, 0x55, 0xb7,
	0x28, 0xf7, 0x3f, 0x5d, 0x08, 0xe3, 0x5d, 0xc0, 0x7c, 0x65, 0x77, 0xf2,
	0x1c, 0x35, 0xa7, 0x1c, 0x8d, 0x69, 0x41, 0x40, 0xa0, 0x04, 0x38, 0x36,
	0x53, 0xaf, 0x78, 0x7c, 0x1e, 0xc1, 0x02, 0x81, 0x81, 0x00, 0xce, 0xfe,
	0x0c, 0x42, 0xbe, 0x47, 0xc6, 0x5c, 0x17, 0x8c, 0x73, 0x0e, 0xfe, 0xfc,
	0x7c, 0x84, 0x92, 0xe7, 0xaa, 0x13, 0x0b, 0x76, 0xa4, 0x59, 0x5e, 0x34,
	0xb3, 0x8d, 0x5a, 0x48, 0xd8, 0xba, 0x7d, 0x55, 0xbd, 0x49, 0x5a, 0xd8,
	0x8b, 0xdd, 0x03, 0x6c, 0x43, 0x37, 0x3c, 0x41, 0x5e, 0x8b, 0xec, 0xee,
	0x0e, 0xb7, 0x2b, 0x75, 0xe2, 0x9e, 0xc9, 0xfa, 0x13, 0x68, 0x1d, 0xb0,
	0x28, 0x27, 0x88, 0x4c, 0x53, 0xf3, 0x0d, 0x52, 0xff, 0xa9, 0xad, 0x1c,
	0x7a, 0x07, 0xa1, 0x9d, 0x4b, 0xb2, 0x9d, 0x0c, 0xd0, 0x1d, 0xf7, 0x71,
	0xeb, 0x2c, 0x22, 0xe9, 0x97, 0x91, 0x05, 0x1c, 0xfb, 0x67, 0x0c, 0xed,
	0x7e, 0xde, 0xc8, 0x2e, 0x30, 0x6e, 0xbf, 0x51, 0x75, 0x56, 0xc0, 0x2a,
	0x2c, 0x2e, 0x6e, 0xf9, 0xbf, 0x93, 0x4d, 0x45, 0x8b, 0x81, 0xa0, 0x02,
	0x78, 0x24, 0x45, 0x5c, 0x20, 0xa5, 0x02, 0x81, 0x81, 0x00, 0x82, 0xb5,
	0xfc, 0xda, 0x89, 0x8c, 0x5b, 0x53, 0x2e, 0x2a, 0x77, 0xed, 0xe5, 0x64,
	0x3d, 0xea, 0x41, 0x11, 0x31, 0x32, 0x3c, 0xca, 0xaa, 0x7a, 0x3d, 0x85,
	0x8f, 0x1d, 0x0b, 0x91, 0xf9, 0xbe, 0xf4, 0x00, 0xd4, 0xe3, 0xae, 0x59,
	0x94, 0x7a, 0x0b, 0x15, 0xa4, 0x88, 0xf2, 0xd8, 0xd7, 0xc4, 0x98, 0xde,
	0x3e, 0x8e, 0x3c, 0xef, 0x3d, 0x53, 0x5e, 0xdc, 0xd1, 0x37, 0x6c, 0xba,
	0xd0, 0xa6, 0x20, 0x10, 0xbc, 0x3a, 0x4b, 0x33, 0xf3, 0xc7, 0x54, 0x1d,
	0x4e, 0x45, 0x9d, 0x93, 0x7d, 0xca, 0xba, 0xc0, 0xa4, 0xbb, 0x23, 0xd6,
	0x9b, 0x0b, 0xe1, 0xa5, 0xb1, 0x57, 0x99, 0xcd, 0xd6, 0x66, 0x3c, 0x3b,
	0xc0, 0xc1, 0xd9, 0x26, 0x3e, 0x71, 0x7d, 0x41, 0xed, 0xd6, 0xdf, 0xb6,
	0x9d, 0x77, 0x45, 0xd2, 0x62, 0xb1, 0xa4, 0x01, 0xec, 0xbb, 0x96, 0x22,
	0x3a, 0xbe, 0xdf, 0x0e, 0xa9, 0xc1, 0x02, 0x81, 0x80, 0x6d, 0x9c, 0x9f,
	0x0c, 0x24, 0x5f, 0x85, 0x0f, 0xa1, 0x8b, 0x84, 0xa1, 0xdc, 0xbc, 0x06,
	0xa4, 0x6d, 0xd1, 0x75, 0x44, 0xaa, 0xbc, 0xe0, 0x4a, 0xfc, 0x94, 0x11,
	0xb6, 0xf3, 0x9b, 0xf1, 0x62, 0xed, 0x2b, 0xdc, 0x49, 0x0a, 0x60, 0xca,
	0x08, 0xbc, 0x68, 0x6f, 0x6b, 0x70, 0x81, 0x87, 0x89, 0xea, 0xf9, 0xed,
	0x74, 0x11, 0x12, 0xdf, 0xad, 0x6d, 0x13, 0x39, 0x4e, 0xeb, 0x60, 0x46,
	0x76, 0x6f, 0x23, 0xa8, 0x01, 0x32, 0x04, 0x37, 0xa3, 0x66, 0xb8, 0x6b,
	0xbb, 0x6b, 0x91, 0xac, 0x0d, 0x7f, 0x74, 0xd2, 0x05, 0x55, 0x99, 0xf8,
	0xa7, 0xdd, 0xa9, 0xbf, 0xe3, 0xfe, 0xba, 0x91, 0x43, 0x3a, 0x3e, 0xb0,
	0x0f, 0x70, 0xe5, 0x61, 0xed, 0x49, 0x2a, 0xd0, 0xb7, 0x01, 0xbb, 0x37,
	0x1b, 0x59, 0x26, 0xd0, 0x97, 0x26, 0xf5, 0x17, 0x74, 0x82, 0x0e, 0xcf,
	0x65, 0xc5, 0xb7, 0x94, 0xf7
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
#endif /* SAMPLE_CONFIG_MG_H */
