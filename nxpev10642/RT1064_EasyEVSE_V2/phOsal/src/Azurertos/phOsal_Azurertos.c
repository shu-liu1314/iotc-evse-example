#include <phOsal.h>
#include <../../intfs/phApp_Init.h>
#include <../../azure-rtos/threadx/common/inc/tx_api.h>

TX_EVENT_FLAGS_GROUP pointer;

phStatus_t phOsal_Init(void)
{
	return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadCreate(phOsal_Thread_t *threadHandle,pphOsal_ThreadObj_t threadObj,pphOsal_StartFunc_t startFunc,void *arg)
{
	//The thread is created in NfcrdlibEx1_BasicDiscoveryLoop.c
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_ThreadDelete(phOsal_Thread_t * threadHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_ThreadChangePrio(phOsal_Thread_t * threadHandle,uint32_t newPrio)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_ThreadExit(void)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_ThreadDelay(phOsal_Ticks_t ticksToSleep)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_EventCreate(phOsal_Event_t * eventHandle, pphOsal_EventObj_t eventObj)
{
	tx_event_flags_create(&pointer, eventObj->pEvtName);
	eventObj->EventHandle = *eventHandle;
	eventObj->intialValue = 0;
	return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventPost(phOsal_Event_t * eventHandle, phOsal_EventOpt_t options, phOsal_EventBits_t FlagsToPost, phOsal_EventBits_t *pCurrFlags)
{
	// Posting event flag
	if(xPortIsInsideInterrupt() == FALSE){
		// Posting event flag
		tx_interrupt_control(TX_INT_ENABLE);
		UINT status;
		//PRINTF("Event Post ");
		status = tx_event_flags_set(&pointer, FlagsToPost, TX_OR);
		tx_interrupt_control(TX_INT_DISABLE);
		return PH_OSAL_SUCCESS;
	}
	else {
		UINT status;
		//PRINTF("Event Post ");
		status = tx_event_flags_set(&pointer, FlagsToPost, TX_OR);
		return PH_OSAL_SUCCESS;
	}
	return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventClear(phOsal_Event_t * eventHandle, phOsal_EventOpt_t options, phOsal_EventBits_t FlagsToClear, phOsal_EventBits_t *pCurrFlags)
{
	if(xPortIsInsideInterrupt() == FALSE){
		tx_interrupt_control(TX_INT_ENABLE);
		UINT status;
		status = tx_event_flags_get(&pointer,FlagsToClear, TX_AND_CLEAR, &pCurrFlags, 0);
		tx_interrupt_control(TX_INT_DISABLE);
		return PH_OSAL_SUCCESS;
	}
	else{
		UINT status;
		status = tx_event_flags_get(&pointer,FlagsToClear, TX_AND_CLEAR, &pCurrFlags, 0);
		return PH_OSAL_SUCCESS;
	}
	return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventPend(volatile phOsal_Event_t * eventHandle, phOsal_EventOpt_t options, phOsal_Ticks_t ticksToWait, phOsal_EventBits_t FlagsToWait, phOsal_EventBits_t *pCurrFlags)
{
	 ULONG actual_flags;
	 UINT status;
	 status = tx_event_flags_get(&pointer,FlagsToWait, TX_OR, &pCurrFlags, ticksToWait);
     //status = tx_event_flags_get(&pointer,FlagsToWait, TX_OR, &pCurrFlags, TX_NO_WAIT);
	 if(pCurrFlags != FlagsToWait)
	 {
		 return PH_OSAL_SUCCESS;
	 }
	 else
	 {
		 return (PH_OSAL_IO_TIMEOUT | PH_COMP_OSAL);
	 }
	 return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventDelete(phOsal_Event_t * eventHandle)
{
	UINT status;
	status = tx_event_flags_delete(&pointer);
	return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_SemCreate(phOsal_Semaphore_t *semHandle,pphOsal_SemObj_t semObj,phOsal_SemOpt_t opt)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_SemPend(phOsal_Semaphore_t * semHandle,phOsal_TimerPeriodObj_t timePeriodToWait)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_SemPost(phOsal_Semaphore_t * semHandle,phOsal_SemOpt_t opt)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_SemDelete(phOsal_Semaphore_t * semHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_MutexCreate(phOsal_Mutex_t * mutexHandle,pphOsal_MutexObj_t mutexObj)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_MutexLock(phOsal_Mutex_t * mutexHandle,phOsal_TimerPeriodObj_t timePeriodToWait)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_MutexUnLock(phOsal_Mutex_t * mutexHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_MutexDelete(phOsal_Mutex_t * mutexHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerCreate(phOsal_Timer_t * timerHandle,pphOsal_TimerObj_t timerObj)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerStart(phOsal_Timer_t * timerHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerStop(phOsal_Timer_t * timerHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerGetCurrent(phOsal_Timer_t * timerHandle,uint32_t * pdwGetElapsedTime)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerModify(phOsal_Timer_t * timerHandle,pphOsal_TimerObj_t timerObj)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}

phStatus_t phOsal_TimerDelete(phOsal_Timer_t * timerHandle)
{
	return PH_OSAL_UNSUPPORTED_COMMAND;
}
