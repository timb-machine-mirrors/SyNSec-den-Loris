#include <shannon.h>
#include <afl.h>

/*  0xc3a0 opped LTE RRC messages have coarse grained the following structure:
 *      |------------|
 * 0x00 |  op        |
 *      |------------|
 * 0x04 |  size      |
 *      |------------| <- end of qiem_header
 * 0x08 |  UNUSED    |
 *      |------------|
 * 0x0c |  pdu type  |
 *      |------------|
 * 0x10 |  pl_size   |
 *      |------------|
 * 0x14 |  asn_pl *  |
 *      |------------|
 *
 * IMPORTANT: the structure changes with other OPs!
 *
 */

const char TASK_NAME[] = "AFL_SAEL3\0";

typedef enum {
    Invalid=0,
    CMD_SUCCESSFUL,
    CMD_UNSUCCESSFUL_TEMP_ERR,
    CMD_UNSUCCESSFUL_PERM_ERR,
    CMD_UNSUCCESSFUL_SIM_ABSENT,
    CMD_UNSUCCESSFUL_EF_ABSENT,
    CMD_UNSUCCESSFUL_SIM_REJECTED,
    CMD_UNSUCCESSFUL_FILE_NOT_FOUND,
    CMD_UNSUCCESSFUL_SIM_DAMAGED,
    CMD_UNSUCCESSFUL_FILE_INVALIDATED,
    CMD_UNSUCCESSFUL_INCOMPATIBLE_FILE_STRUCT,
    CMD_UNSUCCESSFUL_RECORD_NOT_FOUND,
    CMD_UNSUCCESSFUL_PIN_VER_ERR,
    CMD_UNSUCCESSFUL_PARAM_NOT_FOUND,
    CMD_MAX,
} SIM_ResultCode;

typedef struct PACKED {
    uint8_t RefreshRequiredFlag;
    uint8_t UEMode;
    uint8_t CsServiceSupport;
    uint8_t VoiceDomainPref;
    uint8_t MtCallIndToUser;
    uint8_t SimPresentFlag;
    uint8_t field_0x6;
    uint8_t ServiceDomain;
    uint8_t field_0x7;
    uint8_t field_0x8;
    uint8_t DualSimStatus;
    uint8_t DDS;
    uint8_t ImsDDS;
    uint8_t field_0xd;
} Payload_MMC_EMM_INIT_REQ;

typedef struct PACKED {
    struct qitem_header header;
    Payload_MMC_EMM_INIT_REQ pl;
} QItem_MMC_EMM_INIT_REQ;

typedef struct PACKED {
    uint8_t payload[0x658];
} Payload_SIM_MM_READ_ALL_MM_DATA_RSP;

typedef struct PACKED {
    struct qitem_header header;
    Payload_SIM_MM_READ_ALL_MM_DATA_RSP pl;
} QItem_SIM_MM_READ_ALL_MM_DATA_RSP;

typedef struct PACKED {
  uint8_t payload[0x2010];
} Payload_LTE_RRC_CELL_IND;

typedef struct PACKED {
  struct qitem_header header;
  Payload_LTE_RRC_CELL_IND pl;  
} QItem_LTE_RRC_CELL_IND;

typedef struct PACKED {
  uint8_t payload[0x2010];
} Payload_LTE_RRC_EST_CNF;

typedef struct PACKED {
  struct qitem_header header;
  Payload_LTE_RRC_EST_CNF pl;  
} QItem_LTE_RRC_EST_CNF;

typedef struct PACKED {
  uint32_t unk;
  uint32_t pl_size;
  uint8_t *ded_info_nas;
} Payload_LTE_RRC_DATA_IND;

typedef struct PACKED {
  struct qitem_header header;
  Payload_LTE_RRC_DATA_IND pl;  
} QItem_LTE_RRC_DATA_IND;

typedef struct PACKED {
  uint8_t payload[0x4d];
} Payload_SIM_EMM_AUTH_RSP;

typedef struct PACKED {
  struct qitem_header header;
  Payload_SIM_EMM_AUTH_RSP pl;  
} QItem_SIM_EMM_AUTH_RSP;

static uint32_t sael3_qid = 0;
static uint32_t lte_rrc_qid = 0;
static uint32_t mmc_qid = 0;
static uint32_t sim_qid = 0;

void send_MMC_EMM_INIT_REQ(uint16_t dst_qid)
{
  QItem_MMC_EMM_INIT_REQ *item = (QItem_MMC_EMM_INIT_REQ*) pal_MemAlloc(4, sizeof(QItem_MMC_EMM_INIT_REQ), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = mmc_qid;
  item->header.op2 = dst_qid;
  item->header.size = sizeof(QItem_MMC_EMM_INIT_REQ) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3c5c;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.SimPresentFlag = 1;
  item->pl.ServiceDomain = 2;
  item->pl.DualSimStatus = 1;
  item->pl.ImsDDS = 3;
  pal_MsgSendTo(dst_qid, item, 2);
}

void send_SIM_MM_READ_ALL_MM_DATA_RSP(uint16_t dst_qid)
{
  QItem_SIM_MM_READ_ALL_MM_DATA_RSP *item = (QItem_SIM_MM_READ_ALL_MM_DATA_RSP*) pal_MemAlloc(4, sizeof(QItem_SIM_MM_READ_ALL_MM_DATA_RSP), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = sim_qid;
  item->header.op2 = dst_qid;
  item->header.size = sizeof(QItem_SIM_MM_READ_ALL_MM_DATA_RSP) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3cc0;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.payload[0] = CMD_SUCCESSFUL;
  item->pl.payload[1] = 0;  // != 1
  item->pl.payload[5] = 1;  // & 7 == 1
  uint8_t _imsi[] = {0x11, 0x10, 0x02, 0x00, 0x61, 0x33, 0x47, 0x61};
  memcpy(item->pl.payload + 5, _imsi, sizeof(_imsi));  // _IMSI
  item->pl.payload[0x5e2] = 3;  // MncLength == 3
  uint8_t _rai[] = {0xaa, 0xaa, 0xaa};
  memcpy(item->pl.payload + 0x576, _rai, sizeof(_rai));
  pal_MsgSendTo(dst_qid, item, 2);
}

void send_LTE_RRC_CELL_IND(uint16_t dst_qid)
{
  QItem_LTE_RRC_CELL_IND *item = (QItem_LTE_RRC_CELL_IND*) pal_MemAlloc(4, sizeof(QItem_LTE_RRC_CELL_IND), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = lte_rrc_qid;
  item->header.op2 = dst_qid;
  item->header.size = sizeof(QItem_LTE_RRC_CELL_IND) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3c75;
  memset(&item->pl, 0, sizeof(item->pl));
  *(uint32_t *)(item->pl.payload + 4) = 1;
  pal_MsgSendTo(dst_qid, item, 2);
}

void send_LTE_RRC_EST_CNF(uint16_t dst_qid)
{
  QItem_LTE_RRC_EST_CNF *item = (QItem_LTE_RRC_EST_CNF*) pal_MemAlloc(4, sizeof(QItem_LTE_RRC_EST_CNF), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = lte_rrc_qid;
  item->header.op2 = dst_qid;
  item->header.size = sizeof(QItem_LTE_RRC_EST_CNF) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3c77;
  memset(&item->pl, 0, sizeof(item->pl));
  pal_MsgSendTo(dst_qid, item, 2);
}

int fuzz_single_setup()
{
  if (sael3_qid == 0)
    sael3_qid = queuename2id("SAEL3");
  if (lte_rrc_qid == 0)
    lte_rrc_qid = queuename2id("LTERRC");
  if (mmc_qid == 0)
    mmc_qid = queuename2id("MMC");
  if (sim_qid == 0)
    sim_qid = queuename2id("SIM");

  send_MMC_EMM_INIT_REQ(sael3_qid);  // 0x3c5c EmmProc: 1 -> 1

  send_SIM_MM_READ_ALL_MM_DATA_RSP(sael3_qid);  // 0x3cc0 EmmProc: 1 -> 2

  send_LTE_RRC_CELL_IND(sael3_qid);  // 0x3c75 EmmAS: 1 -> 3

  send_LTE_RRC_EST_CNF(sael3_qid);  // 0x3c77 EmmAS: 3 -> 6

  return 1;
}

void *prepare_LTE_RRC_DATA_IND(uint8_t *buf, uint32_t input_size)
{
  QItem_LTE_RRC_DATA_IND * item = pal_MemAlloc(4, sizeof(QItem_LTE_RRC_DATA_IND), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return NULL;
  }

  uint8_t * ded_info_nas = (uint8_t *)pal_MemAlloc(4, input_size, __FILE__, __LINE__);

  MODEM_LOG("Filling the qitem");
  item->header.op1 = lte_rrc_qid;
  item->header.op2 = sael3_qid;
  item->header.size = sizeof(QItem_LTE_RRC_DATA_IND) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3c7b;

  item->pl.unk = 0;
  item->pl.pl_size = input_size;
  memcpy(ded_info_nas, buf, input_size);
  item->pl.ded_info_nas = ded_info_nas;

  return item;
}

void *prepare_SIM_EMM_AUTH_RSP()
{
  QItem_SIM_EMM_AUTH_RSP * item = pal_MemAlloc(4, sizeof(QItem_SIM_EMM_AUTH_RSP), __FILE__, __LINE__);
  if (!item) {
    uart_puts("ALLOC FAILED");
    return NULL;
  }

  uart_puts("[+] Filling the qitem\n");
  item->header.op1 = lte_rrc_qid;
  item->header.op2 = sael3_qid;
  item->header.size = sizeof(QItem_SIM_EMM_AUTH_RSP) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x3ccd;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.payload[0] = 0x82;
  item->pl.payload[1] = 0x8;
  item->pl.payload[2] = 0x10;

  return item;
}

void fuzz_single()
{
  uint32_t input_size;
  uint16_t size;
  
  MODEM_LOG("Getting Work");
  char *buf = getWork(&input_size);
  size = (uint16_t) input_size;

  MODEM_LOG("[+] Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);
  // uart_dump_hex((uint8_t *)buf, size); // Print some for testing

  // Max size before size is forced reduced
  if (size > 1025) {
  startWork(0, 0xffffffff); // memory range to collect coverage
  doneWork(0);
  return;
  }

  void *item = prepare_LTE_RRC_DATA_IND((uint8_t *)buf, input_size);
  // void *item = prepare_SIM_EMM_AUTH_RSP();
  if (!item)
    return;

  MODEM_LOG("FIRE");
  startWork(0, 0xffffffff); // memory range to collect coverage
  pal_MsgSendTo(sael3_qid, item, 2);
  doneWork(0);
  MODEM_LOG("WorkDone");
}
