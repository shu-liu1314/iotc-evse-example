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
/**************************************************************************/
/**                                                                       */
/** GUIX Component                                                        */
/**                                                                       */
/**   User optional settings                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/*                                                                        */
/*  APPLICATION INTERFACE DEFINITION                       RELEASE        */
/*                                                                        */
/*    gx_user.h                                           PORTABLE C      */
/*                                                           6.0          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Kenneth Maxwell, Microsoft Corporation                              */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file contains optional settings. You can enable and disable    */
/*    GUIX features by commenting out or including the definitions below  */
/*    to the implementation of high-performance GUIX UI framework.        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Kenneth Maxwell          Initial Version 6.0           */
/*                                                                        */
/**************************************************************************/

#ifndef GX_USER_H
#define GX_USER_H

/* Should GUIX support multiple threads using the GUIX API simultaneously
   If your application is organized such that only one thread utilizes the
   GUI API services, comment out the definition below to reduce system
   overhead.
 */
/* #define GUIX_DISABLE_MULTITHREAD_SUPPORT */

/* Defined, GUIX disables UTF8 support.  */
/* #define GX_DISABLE_UTF8_SUPPORT */

/* By default GUIX System Timer runs at 20ms.  Modify the value below to
   change GUIX System Timer value. */
/* #define GX_SYSTEM_TIMER_MS  20 */

/* This can be defined to insert an application specific data 
   field into the GX_WIDGET control block */
/* #define GX_WIDGET_USER_DATA */
#endif

