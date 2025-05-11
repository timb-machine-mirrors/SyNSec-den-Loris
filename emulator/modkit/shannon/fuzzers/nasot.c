#include <afl.h>
#include <shannon.h>
#include <nasot.h>

const char TASK_NAME[] = "AFL_NASOT\0";

typedef struct PACKED {
  uint8_t payload[10];
} Payload_MMC_NRMM_INIT_REQ;

typedef struct PACKED {
  struct qitem_header header;
  Payload_MMC_NRMM_INIT_REQ pl;  
} QItem_MMC_NRMM_INIT_REQ;

void send_MM_RRC_DATA_IND(uint8_t *buf, uint32_t input_size) {
  uint8_t *pData = (uint8_t *)pal_MemAlloc(4, input_size + 8, __FILE__, __LINE__);
  if (!pData) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  memcpy(pData + 8, buf, input_size);

  NrmmData *msg = (NrmmData *)pal_MemAlloc(4, sizeof(NrmmData), __FILE__, __LINE__);
  if (!msg) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  msg->field_0x0.field_0x0 = MM_MSG_CLASS;
  msg->field_0x0.field_0x4 = (MM_MSG_CLASS >> 0xc) | MM_MSG_DOMAIN;
  msg->field_0x0.field_0x8 = (MM_MSG_CLASS >> 0x16) | MM_MSG_DOMAIN;  // target_obj_id
  msg->field_0x0.field_0xc = 0x40;  // domain_s
  msg->field_0x0.domain_type = 0;  // domain_d
  msg->field_0x0.field_0x10 = 0x80;  // routing
  memset(msg->field_0x0.field_0x14, 0, 0xc);
  msg->field_0x0.field_0x20 = 4;
  msg->field_0x0.size = 0x48;
  msg->field_0x0.msg_name = "MM_RRC_DATA_IND";
  msg->pl.pData = pData + 8;
  msg->pl.dataLength = input_size;

  (*fake_test)(msg);
}

void send_MMC_NRMM_INIT_REQ()
{
  QItem_MMC_NRMM_INIT_REQ *item = (QItem_MMC_NRMM_INIT_REQ*) pal_MemAlloc(4, sizeof(QItem_MMC_NRMM_INIT_REQ), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = 0xbb;
  item->header.op2 = 0x132;
  item->header.size = sizeof(QItem_MMC_NRMM_INIT_REQ) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x2000;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.payload[0] = 0;

  pal_MsgSendTo(0x132, item, 2);
}

int fuzz_single_setup()
{
  MODEM_LOG("fuzz_single_setup");
  uart_dump_hex((uint8_t *) &SMPF_TASK_CREATED, 4);
  uart_dump_hex((uint8_t *) &fake_test, 4);

  do {
    pal_Sleep(2);
  } while (*SMPF_TASK_CREATED == 0);

  send_MMC_NRMM_INIT_REQ();

  return 1;
}

void fuzz_single()
{
  uint32_t input_size;
  uint16_t size;
  
  MODEM_LOG("Getting Work");
  uint8_t *buf = (uint8_t *)getWork(&input_size);
  size = (uint16_t) input_size;

  MODEM_LOG("[+] Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);
  uart_dump_hex((uint8_t *)buf, size); // Print some for testing

  // Max size before size is forced reduced
  if (size > 0x801) {
  startWork(0, 0xffffffff); // memory range to collect coverage
  doneWork(0);
  return;
  }
  MODEM_LOG("FIRE");
  startWork(0, 0xffffffff); // memory range to collect coverage

  uint8_t *harness = fake_test_harness();
  *harness = 1;
  uint32_t s1 = *(uint32_t *)(buf);
  uint32_t s2 = *(uint32_t *)(buf + 4);
  NrmmStartProcedure_Wrapper(MM_PROC, 1);
  SetMmState(MM_STATE_1, MM_STATE_2, 0x300, 0);
  MODEM_LOG("Sending MM_RRC_DATA_IND...");
  send_MM_RRC_DATA_IND(buf + 8, input_size - 8);

  doneWork(0);
  MODEM_LOG("WorkDone");
}
