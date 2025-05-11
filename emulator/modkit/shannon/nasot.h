#ifndef _NASOT_H
#define _NASOT_H

#include <common.h>
#include <modkit.h>

typedef struct PACKED {
  uint32_t field_0x0;
  uint32_t field_0x4;
  uint32_t field_0x8;
  uint8_t field_0xc;
  uint8_t domain_type;
  uint8_t field_0xe[2];
  uint32_t field_0x10;
  uint8_t field_0x14[0xc];
  uint8_t field_0x20;
  uint16_t field_0x21;
  uint8_t field_0x23;
  uint32_t size;
  char * msg_name;
} astruct_28;

typedef struct PACKED {
  uint8_t *pData;
  uint16_t dataLength;
} MM_RRC_DATA_IND_Payload;

typedef struct PACKED {
  astruct_28 field_0x0;
  MM_RRC_DATA_IND_Payload pl;
} NrmmData;

MODKIT_FUNCTION_SYMBOL(void, fake_test, NrmmData *)
MODKIT_FUNCTION_SYMBOL(void, SetMmState, uint32_t, uint32_t, uint32_t, uint32_t)
MODKIT_FUNCTION_SYMBOL(uint8_t *, fake_test_harness, void)
MODKIT_FUNCTION_SYMBOL(void, NrmmStartProcedure_Wrapper, uint32_t, uint32_t)
MODKIT_DATA_SYMBOL(uint32_t, MM_STATE_1)
MODKIT_DATA_SYMBOL(uint32_t, MM_STATE_2)
MODKIT_DATA_SYMBOL(uint8_t *, SMPF_TASK_CREATED)
MODKIT_DATA_SYMBOL(uint32_t, MM_MSG_CLASS)
MODKIT_DATA_SYMBOL(uint32_t, MM_MSG_DOMAIN)
MODKIT_DATA_SYMBOL(uint32_t, MM_PROC)

#endif // _NASOT_H