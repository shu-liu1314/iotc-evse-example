#ifndef PHOSAL_AZURERTOS_H
#define PHOSAL_AZURERTOS_H
#endif

#define PHOSAL_NVIC_INT_CTRL        ( (volatile uint32_t *) 0xe000ed04 )
#define PHOSAL_NVIC_VECTACTIVE      (0x0000003FU)

#define xPortIsInsideInterrupt()    (((*(PHOSAL_NVIC_INT_CTRL) & PHOSAL_NVIC_VECTACTIVE ) == 0)? FALSE : TRUE)
