/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
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

#include <EVSE_config.h>
#include <stdio.h>

#include "azure/core/az_json.h"
#include "nx_api.h"
#include "nx_azure_iot_hub_client.h"
#include "nx_azure_iot_provisioning_client.h"

/* These are sample files, user can build their own certificate and ciphersuites.  */
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"
#include "fsl_debug_console.h"
#include "fsl_lpuart.h"
#include "se05x_sample.h"
/* These are the includes for NFC reader Library */
#include "NfcrdlibEx1_BasicDiscoveryLoop.h"
#include <phApp_Init.h>
#include "phOsal.h"


#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC                           (10 * 60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC                       (3)
#endif /* SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT                   (60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT */

#ifndef SAMPLE_WAIT_OPTION
#define SAMPLE_WAIT_OPTION                                              (NX_NO_WAIT)
#endif /* SAMPLE_WAIT_OPTION */

/* Sample events */
#define SAMPLE_ALL_EVENTS                                               ((ULONG)0xFFFFFFFF)
#define SAMPLE_CONNECT_EVENT                                            ((ULONG)0x00000001)
#define SAMPLE_INITIALIZATION_EVENT                                     ((ULONG)0x00000002)
#define SAMPLE_METHOD_MESSAGE_EVENT                                     ((ULONG)0x00000004)
#define SAMPLE_DEVICE_TWIN_GET_EVENT                                    ((ULONG)0x00000008)
#define SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT                       ((ULONG)0x00000010)
#define SAMPLE_TELEMETRY_SEND_EVENT                                     ((ULONG)0x00000020)
#define SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT                      ((ULONG)0x00000040)
#define SAMPLE_DISCONNECT_EVENT                                         ((ULONG)0x00000080)
#define SAMPLE_RECONNECT_EVENT                                          ((ULONG)0x00000100)
#define SAMPLE_CONNECTED_EVENT                                          ((ULONG)0x00000200)

/* Sample states */
#define SAMPLE_STATE_NONE                                               (0)
#define SAMPLE_STATE_INIT                                               (1)
#define SAMPLE_STATE_CONNECTING                                         (2)
#define SAMPLE_STATE_CONNECT                                            (3)
#define SAMPLE_STATE_CONNECTED                                          (4)
#define SAMPLE_STATE_DISCONNECTED                                       (5)

#define SAMPLE_DEAFULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)

#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)

#define SAMPLE_PNP_MODEL_ID                                             "dtmi:nxp:evse;2"
#define SAMPLE_PNP_DPS_PAYLOAD                                          "{\"modelId\":\"" SAMPLE_PNP_MODEL_ID "\"}"

#define RED_TEXT(x) "\033[31;1m" x "\033[0m"
#define GREEN_TEXT(x) "\033[32;1m" x "\033[0m"
#define YELLOW_TEXT(x) "\033[33;1m" x "\033[0m"

/* Define Sample context.  */
typedef struct SAMPLE_CONTEXT_STRUCT
{
    UINT                                state;
    UINT                                action_result;
    ULONG                               last_periodic_action_tick;

    TX_EVENT_FLAGS_GROUP                sample_events;

    /* Generally, IoTHub Client and DPS Client do not run at the same time, user can use union as below to
       share the memory between IoTHub Client and DPS Client.

       NOTE: If user can not make sure sharing memory is safe, IoTHub Client and DPS Client must be defined seperately.  */
    union SAMPLE_CLIENT_UNION
    {
        NX_AZURE_IOT_HUB_CLIENT             iothub_client;
#ifdef ENABLE_DPS_SAMPLE
        NX_AZURE_IOT_PROVISIONING_CLIENT    prov_client;
#endif /* ENABLE_DPS_SAMPLE */
    } client;

#define iothub_client client.iothub_client
#ifdef ENABLE_DPS_SAMPLE
#define prov_client client.prov_client
#endif /* ENABLE_DPS_SAMPLE */

} SAMPLE_CONTEXT;

#ifdef ENABLE_DPS_SAMPLE
static UINT sample_dps_entry(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                             UCHAR **iothub_hostname, UINT *iothub_hostname_length,
                             UCHAR **iothub_device_id, UINT *iothub_device_id_length);
#endif /* ENABLE_DPS_SAMPLE */

/* Define Azure RTOS TLS info.  */
static struct app_cert_info root_certs[APP_CERTIFICATE_COUNT];
static NX_SECURE_X509_CERT root_ca_cert[APP_CERTIFICATE_COUNT];

static UCHAR nx_azure_iot_tls_metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG nx_azure_iot_thread_stack[NX_AZURE_IOT_STACK_SIZE / sizeof(ULONG)];

/* Using X509 certificate authenticate to connect to IoT Hub,
   set the device certificate as your device.  */
#if (USE_DEVICE_CERTIFICATE == 1)
extern const unsigned char sample_device_cert_ptr[];
extern int sample_device_cert_len;
extern const unsigned char sample_device_private_key_ptr[];
extern int sample_device_private_key_len;
NX_SECURE_X509_CERT device_certificate;
#endif /* USE_DEVICE_CERTIFICATE */

#if (USE_SE05x_DEVICE_CERTIFICATE == 1)
UCHAR se05x_device_cert[SE05X_CLIENT_CERTIFICATE_SIZE];
size_t se05x_device_certLength = sizeof(se05x_device_cert);
NX_SECURE_X509_CERT device_certificate;
#endif /* USE_SE05x_DEVICE_CERTIFICATE +/

/* Define buffer for IoTHub info. */
#ifdef ENABLE_DPS_SAMPLE
static UCHAR sample_iothub_hostname[SAMPLE_MAX_BUFFER];
static UCHAR sample_iothub_device_id[SAMPLE_MAX_BUFFER];
#endif /* ENABLE_DPS_SAMPLE */

#define SAMPLE_UART_STACK_SIZE            (2048)
#define UART_THREAD_PRIORITY              (16)
#define METER_LPUART            LPUART2
#define METER_LPUART_CLK_FREQ   BOARD_DebugConsoleSrcFreq()
#define METER_LPUART_IRQn       LPUART2_IRQn
#define METER_LPUART_IRQHandler LPUART2_IRQHandler
#define MAX_EVSE_CURRENT                  (16)

/*! @brief Ring buffer size (Unit: Byte). */
#define METER_RING_BUFFER_SIZE 256

/*******************************************************
 * Prototypes
 *******************************************************/
extern void Update_EVSE_Values(void);
extern void Update_Meter_Values(void);
void sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time));
void meter_refresh_entry(ULONG thread_input);

/*******************************************************
 * Variables
 *******************************************************/
/* Define the prototypes for AZ IoT.  */
static NX_AZURE_IOT nx_azure_iot;
static SAMPLE_CONTEXT sample_context;
static volatile UINT sample_connection_status = NX_NOT_CONNECTED;
static UINT exponential_retry_count;

/* Telemetry */
static const az_span telemetry_name_temperature = AZ_SPAN_LITERAL_FROM_STR("temperature");
static const az_span telemetry_name_battery = AZ_SPAN_LITERAL_FROM_STR("battery");
static const az_span telemetry_name_ChargeRate = AZ_SPAN_LITERAL_FROM_STR("ChargeRate");
static const az_span telemetry_name_batterycapacity = AZ_SPAN_LITERAL_FROM_STR("batterycapacity");
static const az_span telemetry_name_chargestatus = AZ_SPAN_LITERAL_FROM_STR("chargestatus");
static const az_span telemetry_name_vehicleid = AZ_SPAN_LITERAL_FROM_STR("vehicleid");
static const az_span telemetry_name_vehicleauthentic = AZ_SPAN_LITERAL_FROM_STR("vehicleauthentic2");
static const az_span telemetry_name_evseid = AZ_SPAN_LITERAL_FROM_STR("evseid");
static const az_span telemetry_name_evselocation = AZ_SPAN_LITERAL_FROM_STR("evselocation");
static const az_span telemetry_name_evselocation_lat = AZ_SPAN_LITERAL_FROM_STR("lat");
static const az_span telemetry_name_evselocation_lon = AZ_SPAN_LITERAL_FROM_STR("lon");
static const az_span telemetry_name_evselocation_alt = AZ_SPAN_LITERAL_FROM_STR("alt");
static const az_span telemetry_name_evselimit = AZ_SPAN_LITERAL_FROM_STR("evselimit");
static const az_span telemetry_name_TimeRemaining = AZ_SPAN_LITERAL_FROM_STR("TimeRemaining");
static const az_span telemetry_name_chargecost = AZ_SPAN_LITERAL_FROM_STR("chargecost");
static const az_span telemetry_name_irms = AZ_SPAN_LITERAL_FROM_STR("irms");
static const az_span telemetry_name_vrms = AZ_SPAN_LITERAL_FROM_STR("vrms");
static const az_span telemetry_name_kwh = AZ_SPAN_LITERAL_FROM_STR("kwh");
static const az_span telemetry_name_firmwareV = AZ_SPAN_LITERAL_FROM_STR("firmwareV");

/* Device command */
static const CHAR terminate_method_name[] = "terminate";
static const az_span method_status_name = AZ_SPAN_LITERAL_FROM_STR("status");
static const az_span method_status_ok = AZ_SPAN_LITERAL_FROM_STR("OK");

/* Twin properties */
static const az_span desired_gridpowerlimit2_property_name = AZ_SPAN_LITERAL_FROM_STR("GridPowerLimit2");
static const az_span desired_Tariff_property_name = AZ_SPAN_LITERAL_FROM_STR("Tariff");
static const az_span desired_tariffcost_property_name = AZ_SPAN_LITERAL_FROM_STR("tariffcost");

static const az_span desired_property_name = AZ_SPAN_LITERAL_FROM_STR("desired");
static const az_span desired_version_property_name = AZ_SPAN_LITERAL_FROM_STR("$version");

static const az_span reported_gridpowerlimit2_property_name = AZ_SPAN_LITERAL_FROM_STR("GridPowerLimit2");
static const az_span reported_Tarff_property_name = AZ_SPAN_LITERAL_FROM_STR("Tariff");
static const az_span reported_tariffcost_property_name = AZ_SPAN_LITERAL_FROM_STR("tariffcost");

static const az_span reported_value_property_name = AZ_SPAN_LITERAL_FROM_STR("value");
static const az_span reported_status_property_name = AZ_SPAN_LITERAL_FROM_STR("ac");
static const az_span reported_version_property_name = AZ_SPAN_LITERAL_FROM_STR("av");
static const az_span reported_description_property_name = AZ_SPAN_LITERAL_FROM_STR("ad");

static const az_span success_response_description = AZ_SPAN_LITERAL_FROM_STR("success");
static const az_span Tariff_response_description = AZ_SPAN_LITERAL_FROM_STR("success");
static const az_span tariffcost_response_description = AZ_SPAN_LITERAL_FROM_STR("success");

/* Device data */
static UCHAR scratch_buffer[256];
uint32_t Temperature = 25;            	 /* EVSE local temperature */
uint32_t GridPowerLimit = 32;         	 /* Grid controlled max power to deliver */
uint32_t desired_gridPowerLimit = 32;
float TariffCost = 0.10;         	     /* Energy Cost per KWh */
float desired_TariffCost = 0.10;
char ChargeStatus[2] = "D";     	     /* Charge state moves from A to D for charging and E..F for errors */
az_span Statestr;
int updateReportedProperties = 0;
uint32_t EvseRating = 16;             	 /* Current rating of charging point in Amps*/
char EvseId[9] = "10071856";             /* charging station SN as Hex string */
az_span Evsestr;
char VehicleId[20] = "14031879";         /* Id of vehicle read from tag */
az_span Vehiclestr;
float ChargeCost = 2.25;         	     /* current charge cost based on charging rate x tariff cost */
uint32_t Battery = 50;               	 /* Vehicle battery level as % */
uint32_t batterycapacity = 48;			 /* Vehicle battery capacity read from tag read in kW */
uint32_t chargingrate = 0;           	 /* Actual kw in use */
uint32_t tariff = 0;		             /* current energy tariff in use ie 0 : 1 : 2 */
uint32_t desired_tariff = 0;
double latitude = 51.50263;			     /* evse location latitude  52.12837*/
double longitude = -0.15087;  		     /* evse location longitude 4.65697*/
double altitude = 0.0;				     /* evse location altitude */
int time_remaining = 150;			 /* Time remaining in minutes */
float irms = 2.0;                        /* meter measured consumption current */
float vrms = 230.0;                      /* meter measured voltage */
float kwh = 890.0;                       /* meter measured power */
char EVSE_State[7] = "STATEA";           /* Status of charging sequence at Meter */
float firmwareV = 1.0;                   /* rt1064 firmware version number */
static int gpl_property_version;
bool vehicleauthentic = true; 	         /* Vehicle authentication status */
az_span Authstr;
static char outstring[12] = "00H:00M:00S"; /* time remaining in iso 8601 format */
az_span  str2send;                       /* need record address and size of outstring in correct format */
uint32_t firstMsg = 1;                   /* Set to 1 for sending initial telemetry, set to 0 for sending remainder of telemetry */
static TX_THREAD thread_request;
static ULONG thread_request_stack[SAMPLE_UART_STACK_SIZE / sizeof(ULONG)];
static void meter_request_entry(ULONG parameter);
static TX_THREAD thread_refresh;
static ULONG thread_refresh_stack[SAMPLE_UART_STACK_SIZE / sizeof(ULONG)];
static TX_EVENT_FLAGS_GROUP event_flags_0;
static TX_MUTEX mutex_UART;
char meterRingBuffer[METER_RING_BUFFER_SIZE];
volatile uint16_t rxIndex; /* Index of the memory to save new arrived data. */
bool new_meterdata = false;

char CardUID[20];
char CardTek[2];    /* A, B, F, V*/
char CardType[4]; /* 1 , 2, 3, P2P */
uint8_t SizeUID;
phacDiscLoop_Sw_DataParams_t       * pDiscLoop;
extern TX_MUTEX mutex_I2C;
uint8_t  sens_res[2]     = {0x04, 0x00};              /* ATQ bytes - needed for anti-collision */
uint8_t  nfc_id1[3]        = {0xA1, 0xA2, 0xA3};  /* user defined bytes of the UID (one is hardcoded) - needed for anti-collision */
uint8_t  sel_res             = 0x40;
uint8_t  nfc_id3            = 0xFA;                          /* NFC3 byte - required for anti-collision */
uint8_t  poll_res[18]    = {0x01, 0xFE, 0xB2, 0xB3, 0xB4, 0xB5,
                                   0xB6, 0xB7, 0xC0, 0xC1, 0xC2, 0xC3,
                                   0xC4, 0xC5, 0xC6, 0xC7, 0x23, 0x45 };
#ifdef PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION
uint32_t aBasicDiscTaskBuffer[BASIC_DISC_DEMO_TASK_STACK];
#else /* uint32_t aBasicDiscTaskBuffer[BASIC_DISC_DEMO_TASK_STACK]; */
#define aBasicDiscTaskBuffer    NULL
#endif /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
/* This is used to save restore Poll Config.
 * If in case application has update/change PollCfg to resolve Tech
 * when Multiple Tech was detected in previous poll cycle
 */
static uint16_t bSavePollTechCfg;

/*******************************************************************************
 * Code
 ******************************************************************************/
void Init_Meter_Uart(void)
{
	lpuart_config_t uart_config;

    /* Set up Meter UART
     * config.baudRate_Bps = 115200U;
     * config.parityMode = kLPUART_ParityDisabled;
     * config.stopBitCount = kLPUART_OneStopBit;
     * config.txFifoWatermark = 0;
     * config.rxFifoWatermark = 0;
     * config.enableTx = false;
     * config.enableRx = false;
     */
    LPUART_GetDefaultConfig(&uart_config);
    uart_config.baudRate_Bps = 115200U;
    uart_config.enableTx     = true;
    uart_config.enableRx     = true;
    LPUART_Init(METER_LPUART, &uart_config, METER_LPUART_CLK_FREQ);
    new_meterdata = false;
    rxIndex = 0;
    /* Enable on RX interrupt. */
    LPUART_EnableInterrupts(METER_LPUART, kLPUART_RxDataRegFullInterruptEnable | kLPUART_RxOverrunFlag);
    EnableIRQ(METER_LPUART_IRQn);
}


void METER_LPUART_IRQHandler(void)
{
	char data;
    uint16_t tmprxIndex = rxIndex;
    UINT status;
    volatile uint32_t uart_status;

    uart_status = LPUART_GetStatusFlags(METER_LPUART);

    if (( kLPUART_RxOverrunFlag) & uart_status)
    {
        /* clear overrun*/
        LPUART_ClearStatusFlags(METER_LPUART, kLPUART_RxOverrunFlag);
    }

    /* Check if new data arrived. */
    if ((kLPUART_RxDataRegFullFlag) & uart_status)
    {

      data = LPUART_ReadByte(METER_LPUART);
       if (tmprxIndex < METER_RING_BUFFER_SIZE)
        {
           meterRingBuffer[rxIndex] = data;
           if (data == '\r')
             {
            	 /* set NUL character at end of data for str function handling*/
            	 meterRingBuffer[rxIndex] = 0;
                 /* Set event flag 0 to wakeup meter_refresh thread.  */
                 status = tx_event_flags_set(&event_flags_0, 0x1, TX_OR);
             }
             rxIndex++;
             /* restrict sequence of rxIndex to 0..255 */
             rxIndex %= METER_RING_BUFFER_SIZE;
        }
    }
    SDK_ISR_EXIT_BARRIER;
}

/* Send an update request to meter to obtain latest measurement values.
 * UART transfer is governed by MuteX as more than once function could
 * attempt access the UART at the same time.
 *
 */
void meter_request_now(void)
{
	uint8_t status;
    uint8_t command_all = 48;   // Ascii 0 Request ALL meter data parameters
    //   uint8_t command_current[] =  "1"; // Request iRMS
    //   uint8_t command_voltage[] = "2"; // Request vRMS
    //   uint8_t command_power[] =   "3"; // Request Power
    //   uint8_t command_status[] =    "4"; // Request STATE
    //   uint8_t command_status[] =    "A"; // Set STATE

    /* Get the UART MuteX with suspension.  */
    status = tx_mutex_get(&mutex_UART, TX_WAIT_FOREVER);
    /* Check status.  */
    if (status != TX_SUCCESS)
    {
    	PRINTF("Could not get MuteX for UART request now/r/n");
    }
    /* send command to Meter board */
    LPUART_WriteByte(METER_LPUART, command_all);

    /* Wait for UART Outputs to complete before entering reduced power mode */
 	while (!(LPUART_GetStatusFlags(METER_LPUART) & kLPUART_TxDataRegEmptyFlag)) {}

 	/* Release the UART MuteX.  */
    status = tx_mutex_put(&mutex_UART);
    /* Check status.  */
    if (status != TX_SUCCESS)
    {
    	PRINTF("Could not release MuteX for UART in request now/r/n");
    }
}


/* Send an update request to meter to obtain latest measurement every 500 ticks.  */
void meter_request_entry(ULONG thread_input)
{
    uint8_t command_all = 48;       // Ascii 0 Request ALL meter data parameters

    /* This thread simply sits in while-forever-sleep loop.  */
    while (1)
    {
    	/* issue update to meter board */
    	meter_request_now();
    	/* Sleep for 500 ticks.  */
        tx_thread_sleep(500);
    }
}

/* Process and assign meter measurements if new values have been received */
void meter_refresh_entry(ULONG thread_input)
{
    UINT status;
    ULONG actual_flags;

    uint8_t numrx;
    uint8_t meterstate;
    float ret;
    char *ptr;
    char *str_ptr;
    uint32_t chartoprocess, myptrdiff;

    char comnum[4] = "";
    char comstr1[4] = "[1]"; /* Current Data */
    char comstr2[4] = "[2]"; /* Voltage Data */
    char comstr3[4] = "[3]"; /* Power Data */
    char comstr4[4] = "[4]"; /* EVSE State */

    /* This thread simply waits for an event in a forever loop.  */
    while (1)
    {

        /* Wait for event flag 0 which is set by the METER_LPUART_IRQHandler only when full packet received from Meter */
        status = tx_event_flags_get(&event_flags_0, 0x1, TX_OR_CLEAR, &actual_flags, TX_WAIT_FOREVER);

        /* Check status.  */
        if ((status != TX_SUCCESS) || (actual_flags != 0x1))
        {

          PRINTF("THREADX error...\r\n");
          break;
        }

        /* process data in meterRingBuffer from index 0 to rxIndex -1 */
      	numrx = rxIndex - 1;
      	chartoprocess = numrx;
      	/* Set pointer to start of receiver array */
      	str_ptr = &meterRingBuffer[0];

      	   while (chartoprocess)
      	   {
      	        ret = strtod(str_ptr, &ptr);
      	        myptrdiff = ptr - str_ptr;
      	        strncpy(comnum, ptr, 3);

      	        if (strcmp (comstr1, comnum)==0)
      	            {
      	            irms = ret;
      	            }
      	        else if (strcmp (comstr2, comnum)==0)
      	            {
      	            vrms = ret;
      	            }
      	        else if (strcmp (comstr3, comnum)==0)
      	            {
      	            kwh = ret;
      	            }
      	        else if (strcmp (comstr4, comnum)==0)
      	            {
      	            meterstate = ret / 1;
      	            switch (meterstate)
      	             {
      	                case 1:
      	                 strcpy(EVSE_State, "STATEA");
      	                 strcpy(ChargeStatus, "A");
      	                 break;
      	                case 2:
      	                 strcpy(EVSE_State, "STATEB");
      	                 strcpy(ChargeStatus, "B");
      	                 break;
      	                case 3:
      	                 strcpy(EVSE_State, "STATEC");
      	                 strcpy(ChargeStatus, "C");
      	                 break;
      	                case 4:
      	                 strcpy(EVSE_State, "STATED");
      	                 strcpy(ChargeStatus, "D");
      	                 break;
      	                case 5:
      	                 strcpy(EVSE_State, "STATEE");
      	                 strcpy(ChargeStatus, "E");
      	                 break;
      	                case 6:
      	                 strcpy(EVSE_State, "STATEF");
      	                 strcpy(ChargeStatus, "F");
      	                 break;
      	                default:
      	                 strcpy(EVSE_State, "eSTATE");
      	                 strcpy(ChargeStatus, "Z");
      	                 break;
      	             }
  	                 Statestr = az_span_create_from_str(ChargeStatus);
  	                 Update_EVSE_Values();
      	            }
      	        ptr = ptr + 3;
      	        str_ptr = ptr;
      	        chartoprocess -= (myptrdiff + 3);
      	   }
        new_meterdata = true;
		Update_Meter_Values();
		rxIndex = 0;
    }
}


/* Move reader to the value of property name */
static UINT sample_json_child_token_move(az_json_reader *json_reader, az_span property_name)
{
    while (az_result_succeeded(az_json_reader_next_token(json_reader)))
    {
        if ((json_reader -> token.kind == AZ_JSON_TOKEN_PROPERTY_NAME) &&
            az_json_token_is_text_equal(&(json_reader -> token), property_name))
        {
           if (az_result_failed(az_json_reader_next_token(json_reader)))
           {
               PRINTF("Failed to read next token\r\n");
               return(NX_NOT_SUCCESSFUL);
           }

           return(NX_AZURE_IOT_SUCCESS);
        }
        else if (json_reader -> token.kind == AZ_JSON_TOKEN_BEGIN_OBJECT)
        {
            if (az_result_failed(az_json_reader_skip_children(json_reader)))
            {
                PRINTF("Failed to skip child of complex object\r\n");
                return(NX_NOT_SUCCESSFUL);
            }
        }
        else if (json_reader -> token.kind == AZ_JSON_TOKEN_END_OBJECT)
        {
        	//PRINTF("Failed to find the token, now at end of message\r\n");
            return(NX_AZURE_IOT_NOT_FOUND);
        }
    }

    return(NX_AZURE_IOT_NOT_FOUND);
}

/* Build reported properties into JSON */
static UINT sample_build_reported_property(UCHAR *buffer_ptr, UINT buffer_size,
                                           UINT *bytes_copied, int gridPowerLimit)
{
    UINT ret;
    az_span buff_span = az_span_create(buffer_ptr, (INT)buffer_size);
    az_json_writer json_builder;

    if (!az_result_failed(az_json_writer_init(&json_builder, buff_span, NULL)) &&
        !az_result_failed(az_json_writer_append_begin_object(&json_builder)) &&
        !az_result_failed(az_json_writer_append_property_name(&json_builder, reported_gridpowerlimit2_property_name)) &&
        !az_result_failed(az_json_writer_append_int32(&json_builder, gridPowerLimit)) &&
		!az_result_failed(az_json_writer_append_property_name(&json_builder, reported_tariffcost_property_name)) &&
		!az_result_failed(az_json_writer_append_double(&json_builder, TariffCost, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
		!az_result_failed(az_json_writer_append_property_name(&json_builder, reported_Tarff_property_name)) &&
		!az_result_failed(az_json_writer_append_int32(&json_builder, tariff)) &&
        !az_result_failed(az_json_writer_append_end_object(&json_builder)))
    {
        *bytes_copied = (UINT)az_span_size(az_json_writer_get_bytes_used_in_destination(&json_builder));
        ret = 0;
    }
    else
    {
        ret = 1;
        PRINTF("Failed to build reported property\r\n");
    }

    return(ret);
}

/* Send property response as reported property */
static UINT sample_send_reported_property(SAMPLE_CONTEXT *context, UINT status, UINT version, az_span description, UINT Properties_2_Update)
{
    az_span buff_span = az_span_create(scratch_buffer, sizeof(scratch_buffer));
    az_json_writer json_builder;
    UINT bytes_copied;
    UINT response_status;
    UINT request_id;
    ULONG reported_property_version;
    uint8_t do_Grid = Properties_2_Update & 1;
    uint8_t do_Tariff = Properties_2_Update & 2;
    uint8_t do_tariffcost = Properties_2_Update & 4;


    if (!az_result_failed(az_json_writer_init(&json_builder, buff_span, NULL)) &&
    	!az_result_failed(az_json_writer_append_begin_object(&json_builder)))
		{
    	  if (do_Grid > 0)
    		  {
    		  /* Add Grid Power Limit Property */
    		  	if  (az_result_failed(az_json_writer_append_property_name(&json_builder, reported_gridpowerlimit2_property_name)) ||
    		  			    az_result_failed(az_json_writer_append_begin_object(&json_builder)) ||
    		  					az_result_failed(az_json_writer_append_property_name(&json_builder, reported_value_property_name)) ||
    		  					az_result_failed(az_json_writer_append_int32(&json_builder, GridPowerLimit)) ||
    		  					az_result_failed(az_json_writer_append_property_name(&json_builder, reported_status_property_name)) ||
    		  					az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)status)) ||
    		  					az_result_failed(az_json_writer_append_property_name(&json_builder, reported_version_property_name)) ||
    		  					az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)version)) ||
    		  					az_result_failed(az_json_writer_append_property_name(&json_builder, reported_description_property_name)) ||
    		  					az_result_failed(az_json_writer_append_string(&json_builder, description)) ||
    		  				az_result_failed(az_json_writer_append_end_object(&json_builder)))
    		  	{
    		  		PRINTF("Report for GridLimit failed \r\n");
    		  		return(NX_NOT_CREATED);
    		  	}
    		  	/* Grid Limit needs updating */
    		  }
    	  if (do_Tariff > 0)
    		  {
    		  /* Add Tariff Property */
   		        if (az_result_failed(az_json_writer_append_property_name(&json_builder, reported_Tarff_property_name)) ||
						az_result_failed(az_json_writer_append_begin_object(&json_builder)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_value_property_name)) ||
							az_result_failed(az_json_writer_append_int32(&json_builder, tariff)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_status_property_name)) ||
							az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)status)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_version_property_name)) ||
							az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)version)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_description_property_name)) ||
							az_result_failed(az_json_writer_append_string(&json_builder, description)) ||
						az_result_failed(az_json_writer_append_end_object(&json_builder)))
				 {
    		  		PRINTF("Report for Tariff failed \r\n");
    		  		return(NX_NOT_CREATED);
				 }
   		     /* Tariff needs updating */
    		  }
    	  if (do_tariffcost > 0)
    		  {
    		  /* Add tariff cost Property */
				if (az_result_failed(az_json_writer_append_property_name(&json_builder, reported_tariffcost_property_name)) ||
						az_result_failed(az_json_writer_append_begin_object(&json_builder)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_value_property_name)) ||
							az_result_failed(az_json_writer_append_double(&json_builder, TariffCost, 2)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_status_property_name)) ||
							az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)status)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_version_property_name)) ||
							az_result_failed(az_json_writer_append_int32(&json_builder, (int32_t)version)) ||
							az_result_failed(az_json_writer_append_property_name(&json_builder, reported_description_property_name)) ||
							az_result_failed(az_json_writer_append_string(&json_builder, description)) ||
						az_result_failed(az_json_writer_append_end_object(&json_builder)))
				 {
   		  		    PRINTF("Report for Tariff failed \r\n");
   		  		    return(NX_NOT_CREATED);
				 }
				 /* tariff cost needs updating */
    		  }

  		  if (az_result_failed(az_json_writer_append_end_object(&json_builder)))
  		     {
  			   return(NX_NOT_SUCCESSFUL);
  		     }
  		  else{
  			bytes_copied = (UINT)az_span_size(az_json_writer_get_bytes_used_in_destination(&json_builder));
  	         if (nx_azure_iot_hub_client_device_twin_reported_properties_send(&(context -> iothub_client),
  	                                                                         scratch_buffer, bytes_copied,
  	                                                                         &request_id, &response_status,
  	                                                                         &reported_property_version,
  	                                                                         (5 * NX_IP_PERIODIC_RATE)))
  	          {
  	            PRINTF("Failed to send reported response\r\n");
  	            return(NX_NOT_SUCCESSFUL);
  	          }
  	         else
  	          {
  	         	gpl_property_version = version;
  	         	PRINTF("\033[0;32m");
  	            PRINTF("Desired property response: %.*s. \r\n", bytes_copied, scratch_buffer);
  	            PRINTF("\033[0m");
  	          }
  		  }
		}
    else{
    	PRINTF("Json writer did not initiate correctly \r\n");
    	return(NX_NOT_SUCCESSFUL);
        }

}

/*
 * Parses a received device twin property document
 * */
static UINT sample_parse_desired_property(SAMPLE_CONTEXT *context, NX_PACKET *packet_ptr, UINT is_partial)
{
    az_span twin_span;
    int parsed_value;
    double parsed_float;
    UINT version;
    az_json_reader json_reader;
    az_json_reader copy_json_reader;
    uint8_t do_update= 0;

  //  PRINTF("Parsing property L370 \r\n");
    if (packet_ptr -> nx_packet_length >
        (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr))
    {
        return(NX_AZURE_IOT_NOT_SUPPORTED);
    }

    twin_span = az_span_create(packet_ptr -> nx_packet_prepend_ptr,
                               (INT)packet_ptr -> nx_packet_length);

    if (az_result_failed(az_json_reader_init(&json_reader, twin_span, NX_NULL)) ||
        az_result_failed(az_json_reader_next_token(&json_reader)))
    {
        PRINTF("Failed to initialize json reader\r\n");
        return(NX_NOT_SUCCESSFUL);
    }

    if (!is_partial && sample_json_child_token_move(&json_reader, desired_property_name))
    {
       PRINTF("Failed to get desired property\r\n");
        return(NX_NOT_SUCCESSFUL);
   }

    copy_json_reader = json_reader;

    if (sample_json_child_token_move(&copy_json_reader, desired_version_property_name) ||
        az_result_failed(az_json_token_get_int32(&(copy_json_reader.token), (int32_t *)&version)))
   {
        PRINTF("Failed to get version\r\n");
        return(NX_NOT_SUCCESSFUL);
   }

    /* Update Grid Power Limit */
    if (!(sample_json_child_token_move(&json_reader, desired_gridpowerlimit2_property_name)) &&
        (!az_result_failed(az_json_token_get_int32(&(json_reader.token), &parsed_value))))
      {
    	desired_gridPowerLimit = parsed_value;
    	GridPowerLimit = parsed_value;
    	/* The EVSE output power rating should follow the Grid Limit when the Grid limit is lower than the MAX EVSE limit */
        if (GridPowerLimit > MAX_EVSE_CURRENT)
         {
         	EvseRating = MAX_EVSE_CURRENT;
         }else
         {
        	EvseRating = GridPowerLimit;
         }
    	do_update = 1;
     }

    /* Update Tariff Rate */
    if (!(sample_json_child_token_move(&json_reader, desired_Tariff_property_name)) &&
        (!az_result_failed(az_json_token_get_int32(&(json_reader.token), &parsed_value))))
     {
        desired_tariff = parsed_value;
        tariff = desired_tariff;
        do_update = do_update + 2;
     }

    /* Update Tariff Cost */
    if (!(sample_json_child_token_move(&json_reader, desired_tariffcost_property_name)) &&
        (!az_result_failed(az_json_token_get_double(&(json_reader.token), &parsed_float))))
     {
        desired_TariffCost = parsed_float;
        TariffCost = parsed_float;
        do_update = do_update + 4;
     }
    if (do_update > 0)
     {
    	sample_send_reported_property(context, 200, (UINT)version, success_response_description, do_update);
    	Update_EVSE_Values();
     }else
     {
    	PRINTF("No properties detected and thus properties will not be updated. \r\n");
     }

    return(NX_AZURE_IOT_SUCCESS);
}

/*
 * Parses a property update message to determine which property to update and its value.
 * Note:
 * The json reader will progress through slice looking for token. If the token is not found then
 * it will progress to the end of the slice. Searching with the same json reader for a new
 * token will fail as it is currently pointing at end of the slice. To overcome this
 * we need individual json readers to be used to find each property token
 * */
static UINT sample_parse_property_update(SAMPLE_CONTEXT *context, NX_PACKET *packet_ptr)
{
    az_span twin_span;
    int parsed_value;
    double parsed_float;
    UINT version;
    az_json_reader json_reader;
    az_json_reader copyG_json_reader;
    az_json_reader copyT_json_reader;
    az_json_reader copytc_json_reader;
    uint8_t do_update= 0;


    if (packet_ptr -> nx_packet_length >
        (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr))
    {
        return(NX_AZURE_IOT_NOT_SUPPORTED);
    }

    twin_span = az_span_create(packet_ptr -> nx_packet_prepend_ptr,
                               (INT)packet_ptr -> nx_packet_length);

    if (az_result_failed(az_json_reader_init(&json_reader, twin_span, NX_NULL)) ||
        az_result_failed(az_json_reader_next_token(&json_reader)))
    {
        PRINTF("Failed to initialise json reader\r\n");
        return(NX_NOT_SUCCESSFUL);
    }

    /* build copy of reader for individual token searches */
    copyG_json_reader = json_reader;
    copyT_json_reader = json_reader;
    copytc_json_reader = json_reader;

    if (sample_json_child_token_move(&json_reader, desired_version_property_name) ||
        az_result_failed(az_json_token_get_int32(&(json_reader.token), (int32_t *)&version)))
   {
        PRINTF("Failed to get version from slice \r\n");
        return(NX_NOT_SUCCESSFUL);
   }

    /* Update Grid Power Limit if present*/
    if (!sample_json_child_token_move(&copyG_json_reader, desired_gridpowerlimit2_property_name) &&
        !az_result_failed(az_json_token_get_int32(&(copyG_json_reader.token), &parsed_value)))
    {
    	desired_gridPowerLimit = parsed_value;
    	GridPowerLimit = parsed_value;
    	/* The EVSE output power rating should follow the Grid Limit when the Grid limit is lower than the MAX EVSE limit */
        if (GridPowerLimit > MAX_EVSE_CURRENT)
         {
         	EvseRating = MAX_EVSE_CURRENT;
         }
        else
         {
        	EvseRating = GridPowerLimit;
         }
      	do_update = 1;
     }

    /* Update Tariff Rate if present */
    if (!sample_json_child_token_move(&copyT_json_reader, desired_Tariff_property_name) &&
        !az_result_failed(az_json_token_get_int32(&(copyT_json_reader.token), &parsed_value)))
    {
        desired_tariff = parsed_value;
        tariff = desired_tariff;
        do_update = do_update + 2;
    }

    /* Update Tariff Cost if present*/
    if (!sample_json_child_token_move(&copytc_json_reader, desired_tariffcost_property_name) &&
        !az_result_failed(az_json_token_get_double(&(copytc_json_reader.token), &parsed_float)))
    {
        desired_TariffCost = parsed_float;
        TariffCost = parsed_float;
        ChargeCost = (TariffCost * chargingrate) /1000;
        do_update = do_update + 4;
    }

    if (do_update > 0)
    {
    	sample_send_reported_property(context, 200, (UINT)version, success_response_description, do_update);
        Update_EVSE_Values();
    }

    return(NX_AZURE_IOT_SUCCESS);
}


/* sample direct method implementation */
static UINT sample_terminate_charging(NX_PACKET *packet_ptr, UCHAR *buffer, UINT buffer_size, UINT *bytes_copied)
{
    UINT status;
    az_json_writer json_builder;
    az_span response = az_span_create(buffer, (INT)buffer_size);
    uint8_t command_state = 65;  // character A

    NX_PARAMETER_NOT_USED(packet_ptr);

    /* Build the method response payload */
    if (az_result_succeeded(az_json_writer_init(&json_builder, response, NULL)) &&
        az_result_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
        az_result_succeeded(az_json_writer_append_property_name(&json_builder, method_status_name)) &&
		az_result_succeeded(az_json_writer_append_string(&json_builder, method_status_ok)) &&
        az_result_succeeded(az_json_writer_append_end_object(&json_builder)))
    {
    	strcpy (ChargeStatus, "A");
    	Statestr = az_span_create_from_str(ChargeStatus);
    	strcpy (EVSE_State, "STATEA");
    	/* send command to Meter board */
    	LPUART_WriteByte(METER_LPUART, command_state);
        status = NX_AZURE_IOT_SUCCESS;
        *bytes_copied = (UINT)az_span_size(az_json_writer_get_bytes_used_in_destination(&json_builder));
    }
    else
    {
        PRINTF("Failed to build getMaxMinReport response \r\n");
        status = NX_NOT_SUCCESSFUL;
    }
    Update_EVSE_Values();
    return(status);
}

static VOID printf_packet(NX_PACKET *packet_ptr)
{
    while (packet_ptr != NX_NULL)
    {
        PRINTF("%.*s", (INT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr),
               (CHAR *)packet_ptr -> nx_packet_prepend_ptr);
        packet_ptr = packet_ptr -> nx_packet_next;
    }
}

static UINT exponential_backoff_with_jitter()
{
    double jitter_percent = (SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT / 100.0) * (rand() / ((double)RAND_MAX));
    UINT base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;

    if (exponential_retry_count < (sizeof(UINT) * 8))
    {
        base_delay = (UINT)((2 << exponential_retry_count) * SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC);
    }

    if (base_delay > SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC)
    {
        base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;
    }
    else
    {
        exponential_retry_count++;
    }

    return((UINT)(base_delay * (1 + jitter_percent)) * NX_IP_PERIODIC_RATE) ;
}

static VOID exponential_backoff_reset()
{
    exponential_retry_count = 0;
}

static VOID connection_status_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT status)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);

    sample_connection_status = status;

    if (status)
    {
        PRINTF("Disconnected from IoTHub!: error code = 0x%08x\r\n", status);
        tx_event_flags_set(&(sample_context.sample_events), SAMPLE_DISCONNECT_EVENT, TX_OR);
    }
    else
    {
        PRINTF(GREEN_TEXT("Connected to IoTHub.\r\n"));
        tx_event_flags_set(&(sample_context.sample_events), SAMPLE_CONNECTED_EVENT, TX_OR);
        exponential_backoff_reset();
    }
}

static VOID message_receive_callback_twin(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_DEVICE_TWIN_GET_EVENT, TX_OR);
}

static VOID message_receive_callback_method(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_METHOD_MESSAGE_EVENT, TX_OR);
}

static VOID message_receive_callback_desire_property(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT, TX_OR);
}

static VOID sample_connect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECT)
    {
        return;
    }

    context -> action_result = nx_azure_iot_hub_client_connect(&(context -> iothub_client), NX_FALSE, SAMPLE_WAIT_OPTION);

    if (context -> action_result == NX_AZURE_IOT_CONNECTING)
    {
        context -> state = SAMPLE_STATE_CONNECTING;
    }
    else if (context -> action_result != NX_SUCCESS)
    {
        sample_connection_status = context -> action_result;
        context -> state = SAMPLE_STATE_DISCONNECTED;
    }
    else
    {
        context -> state = SAMPLE_STATE_CONNECTED;

        context -> action_result =
            nx_azure_iot_hub_client_device_twin_properties_request(&(context -> iothub_client), NX_WAIT_FOREVER);
    }
}

static VOID sample_disconnect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTED &&
        context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> action_result = nx_azure_iot_hub_client_disconnect(&(context -> iothub_client));
    context -> state = SAMPLE_STATE_DISCONNECTED;
}

static VOID sample_connected_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> state = SAMPLE_STATE_CONNECTED;

    context -> action_result =
        nx_azure_iot_hub_client_device_twin_properties_request(&(context -> iothub_client), NX_WAIT_FOREVER);
}

static VOID sample_initialize_iothub(SAMPLE_CONTEXT *context)
{
    UINT status;
#ifdef ENABLE_DPS_SAMPLE
    UCHAR *iothub_hostname = NX_NULL;
    UCHAR *iothub_device_id = NX_NULL;
    UINT iothub_hostname_length = 0;
    UINT iothub_device_id_length = 0;
#else
    UCHAR *iothub_hostname = (UCHAR *)HOST_NAME;
    UCHAR *iothub_device_id = (UCHAR *)DEVICE_ID;
    UINT iothub_hostname_length = sizeof(HOST_NAME) - 1;
    UINT iothub_device_id_length = sizeof(DEVICE_ID) - 1;
#endif /* ENABLE_DPS_SAMPLE */
    NX_AZURE_IOT_HUB_CLIENT* iothub_client_ptr = &(context -> iothub_client);

    if (context -> state != SAMPLE_STATE_INIT)
    {
        return;
    }

    /* Get the I2C mutex with suspension.  */
    status = tx_mutex_get(&mutex_I2C, TX_WAIT_FOREVER);
    /* Check status.  */
    if (status != TX_SUCCESS)
    {
    	PRINTF("Could not get Mutex during IoT Hub Initialisation /r/n");
    }


#ifdef ENABLE_DPS_SAMPLE
/* Run DPS. */
/*
 * You can manually retrieve the hostname and confirm the device id once if statement is complete.
 * This information can be used to directly connect to the IoT Application without the need
 * to connect via DPS
 */
    if ((status = sample_dps_entry(&(context -> prov_client), &iothub_hostname, &iothub_hostname_length,
                                   &iothub_device_id, &iothub_device_id_length)))
    {
        PRINTF("Failed on sample_dps_entry!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }
#endif /* ENABLE_DPS_SAMPLE */

    /* Initialize IoTHub client. */
    if ((status = nx_azure_iot_hub_client_initialize(iothub_client_ptr, &nx_azure_iot,
                                                     iothub_hostname, iothub_hostname_length,
                                                     iothub_device_id, iothub_device_id_length,
                                                     (UCHAR *)MODULE_ID, sizeof(MODULE_ID) - 1,
                                                     _nx_azure_iot_tls_supported_crypto,
                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                     nx_azure_iot_tls_metadata_buffer,
                                                     sizeof(nx_azure_iot_tls_metadata_buffer),
                                                     &root_ca_cert[1])))
    {
        PRINTF("Failed on nx_azure_iot_hub_client_initialize!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }
#if (USE_SE05x_DEVICE_CERTIFICATE == 1)
    #ifndef ENABLE_DPS_SAMPLE
	 se05x_GetCertificate(SSS_CERTIFICATE_INDEX_CLIENT, se05x_device_cert, &se05x_device_certLength );
    #endif
    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate,
                                                        (UCHAR *)se05x_device_cert, (USHORT)se05x_device_certLength,
                                                        NX_NULL, 0,
                                                        (UCHAR *)dummy_device_private_key_ptr, (USHORT)dummy_device_private_key_len,
                                                        DEVICE_KEY_TYPE)))
    {
        PRINTF("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_hub_client_device_cert_set(iothub_client_ptr, &device_certificate)))
    {
        PRINTF("Failed on nx_azure_iot_hub_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#endif

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate,
                                                        (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len,
                                                        NX_NULL, 0,
                                                        (UCHAR *)sample_device_private_key_ptr, (USHORT)sample_device_private_key_len,
                                                        DEVICE_KEY_TYPE)))
    {
        PRINTF("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }
    /* Set device certificate.  */
    else if ((status = nx_azure_iot_hub_client_device_cert_set(iothub_client_ptr, &device_certificate)))
    {
        PRINTF("Failed on nx_azure_iot_hub_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#endif

#if (USE_DEVICE_SYMMETRIC_KEY == 1)

    /* Set symmetric key.  */
    if ((status = nx_azure_iot_hub_client_symmetric_key_set(iothub_client_ptr,
                                                            (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                            sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        PRINTF("Failed on nx_azure_iot_hub_client_symmetric_key_set!\r\n");
    }
#endif /* USE_DEVICE_CERTIFICATE */

    /* Set connection status callback. */
    else if ((status = nx_azure_iot_hub_client_connection_status_callback_set(iothub_client_ptr,
                                                                              connection_status_callback)))
    {
        PRINTF("Failed on connection_status_callback!\r\n");
    }
    else if ((status = nx_azure_iot_hub_client_direct_method_enable(iothub_client_ptr)))
    {
        PRINTF("Direct method receive enable failed!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_device_twin_enable(iothub_client_ptr)))
    {
        PRINTF("device twin enabled failed!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES,
                                                                    message_receive_callback_twin,
                                                                    (VOID *)context)))
    {
        PRINTF("device twin callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_DIRECT_METHOD,
                                                                    message_receive_callback_method,
                                                                    (VOID *)context)))
    {
        PRINTF("device method callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES,
                                                                    message_receive_callback_desire_property,
                                                                    (VOID *)context)))
    {
        PRINTF("device twin desired property callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_model_id_set(iothub_client_ptr, (UCHAR *)SAMPLE_PNP_MODEL_ID, sizeof(SAMPLE_PNP_MODEL_ID) - 1)))
    {
        PRINTF("digital twin modelId set!: error code = 0x%08x\r\n", status);
    }

    if (status)
    {
        nx_azure_iot_hub_client_deinitialize(iothub_client_ptr);
    }

    context -> action_result = status;

    if (status == NX_AZURE_IOT_SUCCESS)
    {
        context -> state = SAMPLE_STATE_CONNECT;
    }

    /* Release the I2C mutex.  */
    status = tx_mutex_put(&mutex_I2C);
    /* Check status.  */
    if (status != TX_SUCCESS)
    {
    	PRINTF("Could not release Mutex during IoT Hub Initialisation /r/n");
    }
}

static VOID sample_connection_error_recover(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_DISCONNECTED)
    {
        return;
    }

    switch (sample_connection_status)
    {
        case NX_AZURE_IOT_SUCCESS:
        {
            PRINTF("already connected\r\n");
        }
        break;

        /* Something bad has happened with client state, we need to re-initialize it */
        case NX_DNS_QUERY_FAILED :
        case NXD_MQTT_ERROR_BAD_USERNAME_PASSWORD :
        case NXD_MQTT_ERROR_NOT_AUTHORIZED :
        {
            PRINTF("re-initializing iothub connection, after backoff\r\n");

            tx_thread_sleep(exponential_backoff_with_jitter());
            nx_azure_iot_hub_client_deinitialize(&(context -> iothub_client));
            context -> state = SAMPLE_STATE_INIT;
        }
        break;

        default :
        {
            PRINTF("reconnecting iothub, after backoff\r\n");

            tx_thread_sleep(exponential_backoff_with_jitter());
            context -> state = SAMPLE_STATE_CONNECT;
        }
        break;
    }
}

static VOID sample_trigger_action(SAMPLE_CONTEXT *context)
{
    switch (context -> state)
    {
        case SAMPLE_STATE_INIT:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_INITIALIZATION_EVENT, TX_OR);
        }
        break;

        case SAMPLE_STATE_CONNECT:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_CONNECT_EVENT, TX_OR);
        }
        break;

        case SAMPLE_STATE_CONNECTED:
        {
            if ((tx_time_get() - context -> last_periodic_action_tick) >= (5 * NX_IP_PERIODIC_RATE))
            {
                context -> last_periodic_action_tick = tx_time_get();
                tx_event_flags_set(&(context -> sample_events), SAMPLE_TELEMETRY_SEND_EVENT, TX_OR);
//              tx_event_flags_set(&(context -> sample_events), SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT, TX_OR);
            }
        }
        break;

        case SAMPLE_STATE_DISCONNECTED:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_RECONNECT_EVENT, TX_OR);
        }
        break;
    }
}

static void sample_direct_method_action(SAMPLE_CONTEXT *sample_context_ptr)
{
    NX_PACKET *packet_ptr;
    UINT status = 0;
    USHORT method_name_length;
    UCHAR *method_name_ptr;
    USHORT context_length;
    VOID *context_ptr;
    UINT dm_status = 404;
    UINT response_payload = 0;

    if (sample_context_ptr -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_hub_client_direct_method_message_receive(&(sample_context_ptr -> iothub_client),
                                                                        (const UCHAR**)&method_name_ptr, &method_name_length,
                                                                        &context_ptr, &context_length,
                                                                        &packet_ptr, NX_WAIT_FOREVER)))
    {
        PRINTF("Direct method receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    PRINTF("Receive method call: %.*s, with payload:", (INT)method_name_length, (CHAR *)method_name_ptr);
    printf_packet(packet_ptr);
    PRINTF("\r\n");

    if ((method_name_length == (sizeof(terminate_method_name) - 1)) &&
        (memcmp((VOID *)method_name_ptr, (VOID *)terminate_method_name, sizeof(terminate_method_name) - 1) == 0))
    {
        dm_status = (sample_terminate_charging(packet_ptr, scratch_buffer, sizeof(scratch_buffer),
                                               &response_payload) != NX_AZURE_IOT_SUCCESS) ? SAMPLE_COMMAND_ERROR_STATUS :
                                                                                             SAMPLE_COMMAND_SUCCESS_STATUS;
    }

    if ((status = nx_azure_iot_hub_client_direct_method_message_response(&(sample_context_ptr -> iothub_client), dm_status,
                                                                         context_ptr, context_length, scratch_buffer,
                                                                         response_payload, NX_WAIT_FOREVER)))
    {
        PRINTF("Direct method response failed!: error code = 0x%08x\r\n", status);
    }

    if (response_payload != 0)
    {
    	PRINTF("Direct method response: dm_status = %d, response_payload = %.*s.\r\n", dm_status, response_payload, scratch_buffer);
    }
    else
    {
    	PRINTF("Direct method response: dm_status = %d.\r\n", dm_status);
    }

    nx_packet_release(packet_ptr);
}

static void sample_device_twin_desired_property_action(SAMPLE_CONTEXT *context)
{
    NX_PACKET *packet_ptr;
    UINT status = 0;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_hub_client_device_twin_desired_properties_receive(&(context -> iothub_client), &packet_ptr,
                                                                                 NX_WAIT_FOREVER)))
    {
        PRINTF("Receive desired property receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf_packet(packet_ptr);
    PRINTF("\r\n");

    sample_parse_property_update(context, packet_ptr);

    nx_packet_release(packet_ptr);
}

static void sample_device_twin_get_action(SAMPLE_CONTEXT *context)
{
    UINT status = 0;
    NX_PACKET *packet_ptr;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_hub_client_device_twin_properties_receive(&(context -> iothub_client), &packet_ptr,
                                                                         NX_WAIT_FOREVER)))
    {
        PRINTF("Twin receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf_packet(packet_ptr);
    PRINTF("\r\n");

    sample_parse_desired_property(context, packet_ptr, NX_FALSE);

    nx_packet_release(packet_ptr);
}



static void sample_device_twin_reported_property_action(SAMPLE_CONTEXT *context)
{
    UINT status = 0;
    UINT response_status;
    UINT request_id;
    UINT reported_properties_length;
    ULONG reported_property_version;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    //PRINTF("Twin reported property action and will build response L917 \r\n");
    if ((status = sample_build_reported_property(scratch_buffer, sizeof(scratch_buffer),
                                                 &reported_properties_length, GridPowerLimit)))
    {
        PRINTF("Build reported property failed: error code = 0x%08x\r\n", status);
        return;
    }

    if ((status = nx_azure_iot_hub_client_device_twin_reported_properties_send(&(context -> iothub_client),
                                                                               scratch_buffer,
                                                                               reported_properties_length,
                                                                               &request_id, &response_status,
                                                                               &reported_property_version,
                                                                               (5 * NX_IP_PERIODIC_RATE))))
    {
        PRINTF("Device twin reported properties failed!: error code = 0x%08x\r\n", status);
        return;
    }

    if ((response_status < 200) || (response_status >= 300))
    {
        PRINTF("device twin report properties failed with code : %d\r\n", response_status);
        return;
    }
    else
    {
    	PRINTF("\033[0;33m"); // Yellow
    	PRINTF("Sent Reported Device Twin Properties Action: %.*s.\r\n", reported_properties_length, scratch_buffer);
    	PRINTF("\033[0m");    // back to default
    }
}


/*
 * Convert remaining time into an iso 8601 formatted time string
 * 00H:00M:00S
 */
static void convert_time_remaining(void)
{
	uint8_t hhremain = 0;                    /* time remaining in hours */
	uint8_t mmremain = 0;                    /* time remaining in hours */
	char HHstr[3] = "00";
	char MMstr[3] = "00";
	char searchchar = 'H';
	char *searchptr;

	  mmremain = time_remaining % 60;
	  hhremain = ((time_remaining - mmremain) / 60);
	  /* convert int to str */
	  itoa(hhremain, HHstr, 10);
	   if (hhremain<10)
	   {
	     HHstr[1]= HHstr[0];
	     HHstr[0]= '0';
	     HHstr[2]= '\0';
	   }
	  itoa(mmremain, MMstr, 10);
	   if (mmremain<10)
	   {
	     MMstr[1]= MMstr[0];
	     MMstr[0]= '0';
	     MMstr[2]= '\0';
	   }
	  /* to build Hours, find character of interest in outstring and returns its ptr */
	  searchptr = strchr(outstring, searchchar);
	  searchptr = searchptr - 2;
	  strncpy(searchptr, HHstr, 2);

	/* to build Minutes, find character of interest in outstring and returns its ptr */
	  searchchar = 'M';
	  searchptr = strchr(outstring, searchchar);
	  searchptr = searchptr - 2;
	  strncpy(searchptr, MMstr, 2);
	  str2send = az_span_create_from_str(outstring);
}


/* Main telemetry function.
 * Note that a subset of the parameters will only be sent once at first connection
 */

static void sample_telemetry_action(SAMPLE_CONTEXT *context, UINT firstMsg)
{
    UINT status = 0;
    NX_PACKET *packet_ptr;
    az_json_writer json_builder;
    UINT buffer_length;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    /* Create a telemetry message packet. */
    if ((status = nx_azure_iot_hub_client_telemetry_message_create(&(context -> iothub_client), &packet_ptr, NX_WAIT_FOREVER)))
    {
        PRINTF("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return;
    }

    /* Build telemetry JSON payload */
    if (firstMsg != 0)
    {
    	Statestr = az_span_create_from_str(ChargeStatus);
    	Evsestr = az_span_create_from_str(EvseId);
    	Vehiclestr = az_span_create_from_str(VehicleId);
    	time_remaining = 150;
    	if (vehicleauthentic)
    	 {
    		Authstr = az_span_create_from_str("PASS");
    	 }
    	else
    	 {
    		Authstr = az_span_create_from_str("FAIL");
    	 }
        /* Only transmit Fist time ie on connect */
		if(!(az_result_succeeded(az_json_writer_init(&json_builder, AZ_SPAN_FROM_BUFFER(scratch_buffer), NULL)) &&
			 az_result_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evseid)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, Evsestr)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_battery)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, Battery)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselimit)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, EvseRating)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_chargestatus)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, Statestr)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_vehicleid)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, Vehiclestr)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_vehicleauthentic)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, Authstr)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_batterycapacity)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, batterycapacity)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_firmwareV)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, firmwareV)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselocation)) &&
			 az_result_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselocation_lat)) &&
			 az_result_succeeded(az_json_writer_append_double(&json_builder, latitude, 6)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselocation_lon)) &&
			 az_result_succeeded(az_json_writer_append_double(&json_builder, longitude, 6)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselocation_alt)) &&
			 az_result_succeeded(az_json_writer_append_double(&json_builder, altitude, 6)) &&
			 az_result_succeeded(az_json_writer_append_end_object(&json_builder))))
		{
			PRINTF("Telemetry message failed to build intial message\r\n");
			nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
			return;
		}
    }
    else
    {
    	/* Subsequent timed transmission */
    	Temperature = (Temperature + 5) % 100;
      	time_remaining = time_remaining - 5;
      	  if (time_remaining <0) time_remaining = 0;
      	convert_time_remaining();
      	chargingrate = kwh;
      	ChargeCost = (TariffCost * chargingrate) /1000;
      	Statestr = az_span_create_from_str(ChargeStatus);
		if(!(az_result_succeeded(az_json_writer_init(&json_builder, AZ_SPAN_FROM_BUFFER(scratch_buffer), NULL)) &&
			 az_result_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_evselimit)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, EvseRating)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_battery)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, Battery)) &&

			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_irms)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, irms)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_vrms)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, vrms)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_kwh)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, kwh)) &&

			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_temperature)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, Temperature)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_chargestatus)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, Statestr)) &&

			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_ChargeRate)) &&
			 az_result_succeeded(az_json_writer_append_int32(&json_builder, chargingrate)) &&
			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_chargecost)) &&
			 az_result_succeeded(az_json_writer_append_double(&json_builder, ChargeCost, DOUBLE_DECIMAL_PLACE_DIGITS)) &&

			 az_result_succeeded(az_json_writer_append_property_name(&json_builder, telemetry_name_TimeRemaining)) &&
			 az_result_succeeded(az_json_writer_append_string(&json_builder, str2send)) &&
			 az_result_succeeded(az_json_writer_append_end_object(&json_builder))))
		{
			PRINTF("Telemetry message failed to build update message\r\n");
			nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
			return;
		}
    }

    buffer_length = (UINT)az_span_size(az_json_writer_get_bytes_used_in_destination(&json_builder));
    if ((status = nx_azure_iot_hub_client_telemetry_send(&(context -> iothub_client), packet_ptr,
                                                         (UCHAR *)scratch_buffer, buffer_length, SAMPLE_WAIT_OPTION)))
    {
        PRINTF("Telemetry message send failed!: error code = 0x%08x\r\n", status);
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return;
    }
    Update_EVSE_Values();
    PRINTF(YELLOW_TEXT("Telemetry Updating...\r\n"));
}

#ifdef ENABLE_DPS_SAMPLE
static UINT sample_dps_entry(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                             UCHAR **iothub_hostname, UINT *iothub_hostname_length,
                             UCHAR **iothub_device_id, UINT *iothub_device_id_length)
{
    UINT status;

    PRINTF("Start Provisioning Client...\r\n");
    /* Initialize IoT provisioning client.  */
    if ((status = nx_azure_iot_provisioning_client_initialize(prov_client_ptr, &nx_azure_iot,
                                                              (UCHAR *)ENDPOINT, sizeof(ENDPOINT) - 1,
                                                              (UCHAR *)ID_SCOPE, sizeof(ID_SCOPE) - 1,
                                                              (UCHAR *)REGISTRATION_ID, sizeof(REGISTRATION_ID) - 1,
                                                              _nx_azure_iot_tls_supported_crypto,
                                                              _nx_azure_iot_tls_supported_crypto_size,
                                                              _nx_azure_iot_tls_ciphersuite_map,
                                                              _nx_azure_iot_tls_ciphersuite_map_size,
                                                              nx_azure_iot_tls_metadata_buffer,
                                                              sizeof(nx_azure_iot_tls_metadata_buffer),
                                                              &root_ca_cert[0])))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_initialize!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Initialize length of hostname and device ID. */
    *iothub_hostname_length = sizeof(sample_iothub_hostname);
    *iothub_device_id_length = sizeof(sample_iothub_device_id);

#if (USE_SE05x_DEVICE_CERTIFICATE == 1)
    se05x_GetCertificate(SSS_CERTIFICATE_INDEX_CLIENT, se05x_device_cert, &se05x_device_certLength );

    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate, (UCHAR *)se05x_device_cert, (USHORT)(USHORT)se05x_device_certLength, NX_NULL, 0,
                                                        (UCHAR *)dummy_device_private_key_ptr, (USHORT)dummy_device_private_key_len, DEVICE_KEY_TYPE)))
    {
        PRINTF("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_provisioning_client_device_cert_set(prov_client_ptr, &device_certificate)))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#endif

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate, (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len, NX_NULL, 0,
                                                        (UCHAR *)sample_device_private_key_ptr, (USHORT)sample_device_private_key_len, DEVICE_KEY_TYPE)))
    {
        PRINTF("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_provisioning_client_device_cert_set(prov_client_ptr, &device_certificate)))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#endif

#if (USE_DEVICE_SYMMETRIC_KEY == 1)

    /* Set symmetric key.  */
    if ((status = nx_azure_iot_provisioning_client_symmetric_key_set(prov_client_ptr, (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                                     sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        PRINTF("Failed on nx_azure_iot_hub_client_symmetric_key_set!: error code = 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */
    else if ((status = nx_azure_iot_provisioning_client_registration_payload_set(prov_client_ptr, (UCHAR *)SAMPLE_PNP_DPS_PAYLOAD,
                                                                                 sizeof(SAMPLE_PNP_DPS_PAYLOAD) - 1)))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_registration_payload_set!: error code = 0x%08x\r\n", status);
    }
    /* Register device */
    else if ((status = nx_azure_iot_provisioning_client_register(prov_client_ptr, NX_WAIT_FOREVER)))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_register!: error code = 0x%08x\r\n", status);
    }

    /* Get Device info */
    else if ((status = nx_azure_iot_provisioning_client_iothub_device_info_get(prov_client_ptr,
                                                                               sample_iothub_hostname, iothub_hostname_length,
                                                                               sample_iothub_device_id, iothub_device_id_length)))
    {
        PRINTF("Failed on nx_azure_iot_provisioning_client_iothub_device_info_get!: error code = 0x%08x\r\n", status);
    }
    else
    {
		*iothub_hostname = sample_iothub_hostname;
		*iothub_device_id = sample_iothub_device_id;
		PRINTF("Registered Device Successfully.\r\n");
		PRINTF("IoTHub Host Name: %s.\r\n", sample_iothub_hostname);
		PRINTF("IoTHub Host length: %d.\r\n", *iothub_hostname_length);
		PRINTF("Device ID: %s.\r\n", sample_iothub_device_id);
    }

    /* Destroy Provisioning Client.  */
    nx_azure_iot_provisioning_client_deinitialize(prov_client_ptr);

    return(status);
}
#endif /* ENABLE_DPS_SAMPLE */

/**
 *
 * Sample Event loop
 *
 *
 *       +--------------+           +--------------+      +--------------+       +--------------+
 *       |              |  INIT     |              |      |              |       |              |
 *       |              | SUCCESS   |              |      |              |       |              +--------+
 *       |    INIT      |           |    CONNECT   |      |  CONNECTING  |       |   CONNECTED  |        | (TELEMETRY |
 *       |              +----------->              +----->+              +------->              |        |  METHOD |
 *       |              |           |              |      |              |       |              <--------+  DEVICETWIN)
 *       |              |           |              |      |              |       |              |
 *       +-----+--------+           +----+---+-----+      +------+-------+       +--------+-----+
 *             ^                         ^   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   | CONNECT           | CONNECTING             |
 *             |                         |   |  FAIL             |   FAIL                 |
 * REINITIALIZE|                RECONNECT|   |                   |                        |
 *             |                         |   |                   v                        |  DISCONNECT
 *             |                         |   |        +----------+-+                      |
 *             |                         |   |        |            |                      |
 *             |                         |   +------->+            |                      |
 *             |                         |            | DISCONNECT |                      |
 *             |                         |            |            +<---------------------+
 *             |                         +------------+            |
 *             +--------------------------------------+            |
 *                                                    +------------+
 *
 *
 *
 */
static VOID sample_event_loop(SAMPLE_CONTEXT *context)
{
    ULONG app_events;
    UINT loop = NX_TRUE;
    UINT firstMsg = 1;


    while (loop)
    {
        /* Pickup IP event flags.  */
        if (tx_event_flags_get(&(context -> sample_events), SAMPLE_ALL_EVENTS, TX_OR_CLEAR, &app_events, 5 * NX_IP_PERIODIC_RATE))
        {
            if (context -> state == SAMPLE_STATE_CONNECTED)
            {
                sample_trigger_action(context);
            }

            continue;
        }

        if (app_events & SAMPLE_CONNECT_EVENT)
        {
            sample_connect_action(context);
        }

        if (app_events & SAMPLE_INITIALIZATION_EVENT)
        {
            sample_initialize_iothub(context);
        }

        if (app_events & SAMPLE_DEVICE_TWIN_GET_EVENT)
        {
        	sample_device_twin_get_action(context);
        }

        if (app_events & SAMPLE_METHOD_MESSAGE_EVENT)
        {
            sample_direct_method_action(context);
        }

        if (app_events & SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT)
        {
        	sample_device_twin_desired_property_action(context);
        }

        if (app_events & SAMPLE_TELEMETRY_SEND_EVENT)
        {
            sample_telemetry_action(context, firstMsg);
            firstMsg = 0;
        }

        if (app_events & SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT)
        {
        	sample_device_twin_reported_property_action(context);
        }

        if (app_events & SAMPLE_DISCONNECT_EVENT)
        {
            sample_disconnect_action(context);
        }

        if (app_events & SAMPLE_CONNECTED_EVENT)
        {
            sample_connected_action(context);
        }

        if (app_events & SAMPLE_RECONNECT_EVENT)
        {
            sample_connection_error_recover(context);
        }

        sample_trigger_action(context);
    }
}

static VOID sample_context_init(SAMPLE_CONTEXT *context)
{
    memset(context, 0, sizeof(SAMPLE_CONTEXT));
    tx_event_flags_create(&(context->sample_events), (CHAR*)"sample_app");
}

static void log_callback(az_log_classification classification, UCHAR *msg, UINT msg_len)
{
    if (classification == AZ_LOG_IOT_AZURERTOS)
    {
        PRINTF("%.*s", msg_len, (CHAR *)msg);
    }
}

void NFC_thread_entry(ULONG thread_input)
{
  phStatus_t    statustmp;
  uint16_t      wTagsDetected = 0;
  uint16_t      wNumberOfTags = 0;
  uint16_t      wEntryPoint;
  uint16_t      wValue;
  uint8_t       bIndex;

	/* Initialise hardware and Stack */
	phApp_CPU_Init();
	phStatus_t            status = PH_ERR_INTERNAL_ERROR;
	phNfcLib_Status_t     dwStatus;

	#ifdef PH_PLATFORM_HAS_ICFRONTEND
			phNfcLib_AppContext_t AppContext = {0};
	#endif /* PH_PLATFORM_HAS_ICFRONTEND */

	#ifndef PH_OSAL_NULLOS
			phOsal_ThreadObj_t BasicDisc;
	#endif /* PH_OSAL_NULLOS */

	/* Perform OSAL Initialisation. */
	(void)phOsal_Init();

	status = phbalReg_Init(&sBalParams, sizeof(phbalReg_Type_t));
	CHECK_STATUS(status);

	AppContext.pBalDataparams = &sBalParams;
	dwStatus = phNfcLib_SetContext(&AppContext);
	CHECK_NFCLIB_STATUS(dwStatus);

	/* Initialise library */

	dwStatus = phNfcLib_Init();
	CHECK_NFCLIB_STATUS(dwStatus);

	if(dwStatus != PH_NFCLIB_STATUS_SUCCESS)return;

	/* Set the generic pointer */
	pHal = phNfcLib_GetDataParams(PH_COMP_HAL);
	pDiscLoop = phNfcLib_GetDataParams(PH_COMP_AC_DISCLOOP);

	/* Initialize other components that are not initialised by NFCLIB and configure Discovery Loop. */
	status = phApp_Comp_Init(pDiscLoop);
	CHECK_STATUS(status);
	if(status != PH_ERR_SUCCESS)return;

	/* Configure the IRQ */
	status = phApp_Configure_IRQ();
	CHECK_STATUS(status);
	if(status != PH_ERR_SUCCESS) return;

	//Now we can start with example

	status = phApp_HALConfigAutoColl();
	CHECK_STATUS(status);

	/* Get Poll Configuration */
	status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, &bSavePollTechCfg);
	CHECK_STATUS(status);
	/* Start in poll mode */
	wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
	status = PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED;

	    while(1)
	    {
	        /* Switch off RF field */
	        statustmp = phhalHw_FieldOff(pHal);
	        CHECK_STATUS(statustmp);

	        /* Set Discovery Poll State to Detection */
	        statustmp = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
	        CHECK_STATUS(statustmp);

	        /* Set Poll Configuration */
	        statustmp = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, bSavePollTechCfg);
	        CHECK_STATUS(statustmp);

	#ifdef PH_EXAMPLE1_LPCD_ENABLE

	#ifdef NXPBUILD__PHHAL_HW_RC663

	        if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL)
	#else
	        /* Configure LPCD */
	        if ((status & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED)
	#endif
	        {
	            status = phApp_ConfigureLPCD();
	            CHECK_STATUS(status);
	        }

	        /* Bool to enable LPCD feature. */
	        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_ON);
	        CHECK_STATUS(status);
	#endif /* PH_EXAMPLE1_LPCD_ENABLE */

	        /* Start discovery loop */
	        status = phacDiscLoop_Run(pDiscLoop, wEntryPoint);

	        if(wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL)
	        {
	            if((status & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_TECH_DETECTED)
	            {
	                PRINTF (" \n\r Multiple technology detected: \n\r");

	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                CHECK_STATUS(status);

	                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_A))
	                {
	                    DEBUG_PRINTF (" \tType A detected... \n\r");
	                }
	                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_B))
	                {
	                    PRINTF (" \tType B detected... \n\r");
	                }
	                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_F212))
	                {
	                    PRINTF (" \tType F detected with baud rate 212... \n\r");
	                }
	                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_F424))
	                {
	                    PRINTF (" \tType F detected with baud rate 424... \n\r");
	                }
	                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_V))
	                {
	                    PRINTF(" \tType V / ISO 15693 / T5T detected... \n\r");
	                }

	                /* Select 1st Detected Technology to Resolve*/
	                for(bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++)
	                {
	                    if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, (1 << bIndex)))
	                    {
	                        /* Configure for one of the detected technology */
	                        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, (1 << bIndex));
	                        CHECK_STATUS(status);
	                        break;
	                    }
	                }

	                /* Print the technology resolved */
	                phApp_PrintTech((1 << bIndex));

	                /* Set Discovery Poll State to collision resolution */
	                status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION);
	                CHECK_STATUS(status);

	                /* Restart discovery loop in poll mode from collision resolution phase */
	                status = phacDiscLoop_Run(pDiscLoop, wEntryPoint);
	            }

	            if((status & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_DEVICES_RESOLVED)
	            {
	                /* Get Detected Technology Type */
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                CHECK_STATUS(status);

	                /* Get number of tags detected */
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
	                CHECK_STATUS(status);

	                PRINTF (" \n\r Multiple cards resolved: %d cards \n\r",wNumberOfTags);
	                phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTagsDetected);

	                if(wNumberOfTags > 1)
	                {
	                    /* Get 1st Detected Tag and Activate device at index 0 */
	                    for(bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++)
	                    {
	                        if(PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, (1 << bIndex)))
	                        {
	                            PRINTF("\t Activating one card...\n\r");
	                            status = phacDiscLoop_ActivateCard(pDiscLoop, bIndex, 0);
	                            break;
	                        }
	                    }

	                    if(((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) ||
	                            ((status & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) ||
	                            ((status & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND))
	                    {
	                        /* Get Detected Technology Type */
	                        status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                        CHECK_STATUS(status);

	                        phApp_PrintTagInfo(pDiscLoop, 0x01, wTagsDetected);
	                    }
	                    else
	                    {
	                        PRINT_INFO("\t\tCard activation failed...\n\r");
	                    }
	                }
	                /* Switch to LISTEN mode after POLL mode */
	            }
	            else if (((status & PH_ERR_MASK) == PHAC_DISCLOOP_NO_TECH_DETECTED) ||
	                    ((status & PH_ERR_MASK) == PHAC_DISCLOOP_NO_DEVICE_RESOLVED))
	            {
	                /* Switch to LISTEN mode after POLL mode */
	            }
	            else if((status & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFON)
	            {
	                /*
	                 * If external RF is detected during POLL, return back so that the application
	                 * can restart the loop in LISTEN mode
	                 */
	            }
	            else if((status & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND)
	            {
	                PRINTF (" \n\r Device having T4T and NFC-DEP support detected... \n\r");

	                /* Get Detected Technology Type */
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                CHECK_STATUS(status);

	                phApp_PrintTagInfo(pDiscLoop, 1, wTagsDetected);

	                /* Switch to LISTEN mode after POLL mode */
	            }
	            else if((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED)
	            {
	                PRINTF (" \n\r Card detected and activated successfully... \n\r");
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
	                CHECK_STATUS(status);

	                /* Get Detected Technology Type */
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                CHECK_STATUS(status);

	                phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTagsDetected);
				    PRINTF(" Card UID: %s \r\n", CardUID);
				    PRINTF(" Card Tek: %s \r\n", CardTek);
				    PRINTF("Card Type: %s \r\n", CardType);
				    PRINTF(" UID Size: %d \r\n", SizeUID);

				    memset(VehicleId, '\0',sizeof(VehicleId));
				    strcpy(VehicleId, CardUID);
				    /* set flag to transmit Vehicle ID */
				    firstMsg = 1;
				    /* Switch to LISTEN mode after POLL mode */
	            }
	            else if((status & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED)
	            {
	                PRINTF (" \n\r Active target detected... \n\r");
	                /* Switch to LISTEN mode after POLL mode */
	            }
	            else if((status & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED)
	            {
	                PRINTF (" \n\r Passive target detected... \n\r");

	                /* Get Detected Technology Type */
	                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
	                CHECK_STATUS(status);

	                phApp_PrintTagInfo(pDiscLoop, 1, wTagsDetected);

	                /* Switch to LISTEN mode after POLL mode */
	            }
	            else if ((status & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED)
	            {
	                /* LPCD is succeed but no tag is detected. */
	            }
	            else
	            {
	                if((status & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE)
	                {
	                    status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
	                    CHECK_STATUS(status);
	                    DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
	                }
	                else
	                {
	                    DEBUG_ERROR_PRINT(PrintErrorInfo(status));
	                }
	            }
	            /* Update the Entry point to LISTEN mode. */
	            wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
	        }
	        else
	        {
	            if((status & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFOFF)
	            {
	                /*
	                 * Enters here if in the target/card mode and external RF is not available
	                 * Wait for LISTEN timeout till an external RF is detected.
	                 * Application may choose to go into standby at this point.
	                 */
	                status = phhalHw_EventConsume(pHal);
	                CHECK_STATUS(status);

	                status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_RFON_INTERRUPT, PH_ON);
	                CHECK_STATUS(status);

	                status = phhalHw_EventWait(pHal, LISTEN_PHASE_TIME_MS);
	                if((status & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT)
	                {
	                    wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
	                }
	                else
	                {
	                    wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
	                }
	            }
	            else
	            {
	                if((status & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVATED_BY_PEER)
	                {
	                    PRINTF (" \n\r Device activated in listen mode... \n\r");
	                }
	                else if ((status & PH_ERR_MASK) == PH_ERR_INVALID_PARAMETER)
	                {
	                    /* In case of Front end used is RC663, then listen mode is not supported.
	                     * Switch from listen mode to poll mode. */
	                }
	                else
	                {
	                    if((status & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE)
	                    {
	                        status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
	                        CHECK_STATUS(status);
	                        DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
	                    }
	                    else
	                    {
	                        DEBUG_ERROR_PRINT(PrintErrorInfo(status));
	                    }
	                }

	                /* On successful activated by Peer, switch to LISTEN mode */
	                wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
	            }
	        }
	      tx_thread_sleep(50);
	    }
	}

void sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    UINT status = 0;

    nx_azure_iot_log_init(log_callback);

    Init_Meter_Uart();

    /* Create the event flags group used by Meter UART  */
    if (status = (tx_event_flags_create(&event_flags_0, "event flags 0")))
      {
 	   PRINTF("Failed to create Meter event flags in sample_entry !: error code = 0x%08x\r\n", status);
      }
    /* Create MuteX to handle UART access between Host and Meter */
   status = tx_mutex_create(&mutex_UART, "mutex UART", TX_NO_INHERIT);
    if (status != TX_SUCCESS)
    {
    	PRINTF("Could not create  Mutex during sample helper /r/n");
    }

     if ((status = tx_thread_create(&thread_refresh, "Meter Refresh Thread",
                                    meter_refresh_entry, 0,
                                    (UCHAR *)thread_refresh_stack, SAMPLE_UART_STACK_SIZE,
 								   UART_THREAD_PRIORITY, UART_THREAD_PRIORITY,
                                    TX_NO_TIME_SLICE, TX_AUTO_START)))
      {
     	PRINTF("Failed to create Meter Refresh Thread!: error code = 0x%08x\r\n", status);
      }

    if ((status = tx_thread_create(&thread_request, "Meter Request Thread",
      		                       meter_request_entry, 0,
  								   (UCHAR *)thread_request_stack, SAMPLE_UART_STACK_SIZE,
  								   1, 1,
  								   TX_NO_TIME_SLICE, TX_AUTO_START)))
        {
         PRINTF("Failed to create Meter Request Thread!: error code = 0x%08x\r\n", status);
        }


    /* Create Azure IoT handler.  */
    if ((status = nx_azure_iot_create(&nx_azure_iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr,
                                      nx_azure_iot_thread_stack, sizeof(nx_azure_iot_thread_stack),
                                      NX_AZURE_IOT_THREAD_PRIORITY, unix_time_callback)))
    {
        PRINTF("Failed on nx_azure_iot_create!: error code = 0x%08x\r\n", status);
        return;
    }

    /* Initialize CA certificate. */
    root_certs[0].data = _nx_azure_iot_root_cert;
    root_certs[0].size = _nx_azure_iot_root_cert_size;
    root_certs[1].data = _nx_azure_iot_root_cert_2;
    root_certs[1].size = _nx_azure_iot_root_cert_size_2;
//    root_certs[2].data = _nx_azure_iot_root_cert_3;
//    root_certs[2].size = _nx_azure_iot_root_cert_size_3;

    for (int i = 0; i < 2; i++)
    {
        /* Initialize CA certificates.  */
        status = nx_secure_x509_certificate_initialize(&root_ca_cert[i],
                                                       (UCHAR *)root_certs[i].data, (USHORT)root_certs[i].size,
                                                       NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
        if (status != NX_SECURE_X509_SUCCESS)
        {
            PRINTF("Failed to initialize ROOT CA certificate #%d!: error code = 0x%08x\r\n", i, status);
            nx_azure_iot_delete(&nx_azure_iot);
            return;
        }
    }

    sample_context_init(&sample_context);

    sample_context.state = SAMPLE_STATE_INIT;
    tx_event_flags_set(&(sample_context.sample_events), SAMPLE_INITIALIZATION_EVENT, TX_OR);

    /* Handle event loop */
    sample_event_loop(&sample_context);

    nx_azure_iot_delete(&nx_azure_iot);
}
