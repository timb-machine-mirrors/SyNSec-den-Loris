// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
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

const char TASK_NAME[] = "AFL_LTE_RRC\0";
struct qitem_lte_rrc {
  struct qitem_header header;
  uint32_t unused;
  uint32_t pdu_type;
  uint32_t pl_size;
  char * asn_pl;
} PACKED;

static uint32_t qid;
static struct pal_event_group * group;



int fuzz_single_setup()
{
  qid = queuename2id("LTERRC");
  group = eventname2addr("LTE_RRC_");

  static struct pal_event_group **pp_group = 0x485ef118;
  group = *pp_group;

  uint8_t *enable_debug = (uint8_t *)0x484fd1d8;
  *enable_debug = 0;

  return 1;
}
void fuzz_single()
{
    uint32_t input_size;
    uint16_t size;
    uart_puts("[+] Allocating Qitem\n");
    struct qitem_lte_rrc * item = pal_MemAlloc(4, sizeof(struct qitem_lte_rrc), __FILE__, __LINE__);
    if (!item) {
      uart_puts("ALLOC FAILED");
      return;
    }
    uart_puts("[+] Getting Work\n");
    char * buf = getWork(&input_size);
    size = (uint16_t) input_size;

    uart_puts("[+] Received n bytes: ");
    uart_dump_hex((uint8_t *)buf, size); // Print some for testing
    // uint8_t *rrc_state = (uint8_t *)0x42467c4c;
    // uint8_t *rrc_substate = (uint8_t *)0x42467c50;
    // uint8_t *emm_proc = (uint8_t *)0x425299e1;
    // uint8_t *emm_as = (uint8_t *)0x425299e4;
    // uint8_t *emm_mrg = (uint8_t *)0x425299f8;
    // *rrc_state = (uint8_t)4;
    // *rrc_substate = (uint8_t)0;
    // *emm_proc = (uint8_t)2;
    // *emm_as = (uint8_t)6;
    // *emm_mrg = (int8_t)6;

    // Max size before size is forced reduced
    if (size > 1025) {
    startWork(0, 0xffffffff); // memory range to collect coverage
    doneWork(0);
    return;
    }

    // char * asn_pl = pal_MemAlloc(4, input_size - 1, __FILE__, __LINE__);
    char * asn_pl = pal_MemAlloc(4, input_size, __FILE__, __LINE__);

    uart_puts("[+] Filling the qitem\n");
    item->header.msgGroup = 0;
    item->header.size = sizeof(struct qitem_lte_rrc) - sizeof(struct qitem_header);
    item->header.op = SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID;
    item->unused = 0x00;
    // item->pdu_type = buf[0];
    item->pdu_type = 2;
    // item->pl_size = (input_size -1); //
    item->pl_size = (input_size); //

    // memcpy(asn_pl, buf+1, input_size - 1);
    memcpy(asn_pl, buf, input_size);
    item->asn_pl = asn_pl;


    uart_puts("[+] FIRE\n");
    startWork(0, 0xffffffff); // memory range to collect coverage
    pal_MsgSendTo(qid, item, 2);
    uart_puts("[+] Setting Event\n");
    uart_dump_hex((uint8_t *) group, 4);
    uart_dump_hex((uint8_t *) &pal_SmSetEvent, 4);
    pal_SmSetEvent(&group, 4);
    uart_puts("[+] Event set\n");
    doneWork(0);
    uart_puts("[+] WorkDone\n");
}
