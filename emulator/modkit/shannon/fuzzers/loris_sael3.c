#include <afl.h>
#include <shannon.h>
#include <nasot.h>

const char TASK_NAME[] = "LORIS_SAEL3\0";

/*  Loris input has the following structure:
 *      |--------------------|
 * 0x00 |  size              |
 *      |--------------------|
 * 0x04 |  VendorInput type  |
 *      |--------------------|
 * 0x08 |  ShannonInput type |
 *      |--------------------|
 * 0x0c |  Message Seq. len  |
 *      |--------------------|
 * 0x14 |  Vec of messages   |
 *      |--------------------|
 *
 * The SAEL3 message structure:
 *      |--------------------|
 * 0x00 |  QOp type          |
 *      |--------------------|
 * 0x04 |  QOp               |
 *      |--------------------|
 * 0x08 |  ShannonInput type |
 *      |--------------------|
 * 0x0c |  Message Seq. len  |
 *      |--------------------|
 * 0x14 |  Vec of messages   |
 *      |--------------------|
 *
 */

void set_pre_state();

#define QUEUE_NAME_SZ 64

#define STREAM_TO_BYTE(u8, p, r, handle)                       \
do {                                                              \
    if ((r) < 1) { handle; }                                      \
    (u8) = (uint8_t)(*(p)); \
    (p) += 1;                                                     \
    (r) -= 1;                                                     \
} while (0)

#define STREAM_TO_UINT16(u16, p, r, handle)                       \
do {                                                              \
    if ((r) < 2) { handle; }                                      \
    (u16) = ((uint16_t)(*(p)) + (((uint16_t)(*((p) + 1))) << 8)); \
    (p) += 2;                                                     \
    (r) -= 2;                                                     \
} while (0)

#define STREAM_TO_UINT32(u32, p, r, handle)                           \
do {                                                                  \
    if ((r) < 4) { handle; }                                          \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16) +                     \
             ((((uint32_t)(*((p) + 3)))) << 24));                     \
    (p) += 4;                                                         \
    (r) -= 4;                                                         \
} while (0)

#define STREAM_TO_UINT64(u32, p, r, handle)                           \
do {                                                                  \
    if ((r) < 8) { handle; }                                          \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16) +                     \
             ((((uint32_t)(*((p) + 3)))) << 24));                     \
    (p) += 8;                                                         \
    (r) -= 8;                                                         \
} while (0)

#define STREAM_TO_ARRAY(arr, p, len, r, handle)                        \
do {                                                                   \
    if ((r) < (len)) { handle; }                                       \
    unsigned int ijk;                                                  \
    for (ijk = 0; ijk < (len); ijk++) ((uint8_t*)(arr))[ijk] = *(p)++; \
    (r) -= (len);                                                      \
} while (0)

#define STREAM_MBOX_NAME_TO_QID(qid, p, r)                           \
do {                                                                 \
    uint32_t length = 0;                                             \
    char name[QUEUE_NAME_SZ + 1] = {0};                              \
                                                                     \
    STREAM_TO_UINT64(length, p, r, return 1);                        \
    if (length > QUEUE_NAME_SZ) { return 1; }                        \
    STREAM_TO_ARRAY(name, p, length, r, return 1);                   \
    name[length] = 0;                                                \
    qid = queuename2id(name); /* TODO: check if qid is invalid */    \
    return 0;                                                        \
} while(0)

#define STREAM_TO_QITEM_HEADER(header, p, r)                 \
do {                                                         \
    uint32_t op_type = 0;                                    \
    STREAM_TO_UINT32(op_type, p, r, return 1);               \
    switch (op_type)                                         \
    {                                                        \
    case 0 /* op */:                                         \
        STREAM_TO_UINT32((header).op, p, r, return 1);       \
        break;                                               \
    case 1 /* mbox */:                                       \
        STREAM_TO_UINT16((header).src_qid, p, r, return 1);  \
        STREAM_TO_UINT16((header).dst_qid, p, r, return 1);  \
        break;                                               \
    case 2 /* mbox name */:                                  \
        STREAM_MBOX_NAME_TO_QID((header).src_qid, p, r);     \
        STREAM_MBOX_NAME_TO_QID((header).dst_qid, p, r);     \
        break;                                               \
    default:                                                 \
        return 1;                                            \
    }                                                        \
    STREAM_TO_UINT16((header).size, p, r, return 1);         \
    STREAM_TO_UINT16((header).msg_group, p, r, return 1);    \
} while (0)

#define STREAM_TO_PAYLOAD(payload, pl_size, p, r)                       \
do {                                                                    \
    uint32_t pl_idx = 0, pdu_type = 0, field_type = 0;                  \
    uint32_t num_fields = 0, length = 0;                                \
    STREAM_TO_UINT64(num_fields, p, r, return 2);                       \
    for (uint32_t i = 0; i < num_fields; ++i) {                         \
        STREAM_TO_UINT32(pdu_type, p, r, return 3);                     \
        switch (pdu_type)                                               \
        {                                                               \
        case 0 /* array */:                                             \
            STREAM_TO_UINT32(field_type, p, r, return 1);               \
            STREAM_TO_UINT64(length, p, r, return 4);                   \
            MODEM_LOG("payload.field[%d].length=%d", i, length);        \
            if (length > 0xffff) { return 5; }                          \
            STREAM_TO_ARRAY(payload + pl_idx, p, length, r, return 6);  \
            pl_idx += (uint32_t)length;                                 \
            break;                                                      \
        case 1 /* indir_u32 */:                                         \
            STREAM_TO_UINT32(field_type, p, r, return 1);               \
            STREAM_TO_UINT64(length, p, r, return 7);                   \
            MODEM_LOG("payload.field::<type=%d>[%d].length=%d", field_type, i, length);  \
            if (length > 0xffff) { return 8; }                          \
            *(uint32_t *)(payload + pl_idx) = (uint32_t)length;         \
            pl_idx += (uint32_t)4;                                      \
            uint8_t *buffer = MALLOC((uint32_t)length);                 \
            STREAM_TO_ARRAY(buffer, p, length, r, return 9);            \
            *(uint32_t *)(payload + pl_idx) = (uint32_t)buffer;         \
            pl_idx += 4;                                                \
            break;                                                      \
        default:                                                        \
            return 10;                                                  \
        }                                                               \
        if (pl_idx > pl_size) { return 11; }                            \
    }                                                                   \
} while (0)

typedef struct {
    union {
        struct {
            uint16_t src_qid;
            uint16_t dst_qid;
        };
        uint32_t op;
    };
    uint16_t size;
    uint16_t msg_group;
} QItemHeader;

typedef struct {
    QItemHeader header;
    uint8_t payload[0];
} QItem;

// typedef struct PACKED {
//     uint8_t *addr;
//     uint32_t size;
// } State;

typedef struct PACKED {
    uint8_t *addr;
    uint32_t size;
    uint32_t value;
} StateValue;

typedef int error_t;

static uint32_t sael3_qid = 0;
static StateValue *p_pre_cond_vars;
static uint32_t num_pre_cond_vars = 0;
static StateValue *p_post_mem_vars;
static uint32_t num_post_mem_vars = 0;
static uint8_t vars_type = 0;

error_t send_qitems(uint8_t *buf, uint32_t size, uint32_t dst_qid)
{
    if (size < 4) {
        return 1;
    }

    uint32_t num_bytes = 0, remaining_bytes = 4;
    uart_dump_hex(buf, 4);
    STREAM_TO_UINT32(num_bytes, buf, remaining_bytes, return 2);
    MODEM_LOG("read_messages::num_bytes=0x%x, buf=0x%08x", num_bytes, (uint32_t)buf);
    if (num_bytes + 4 != size) { return 3; }
    remaining_bytes = num_bytes;

    uint32_t vendor_input_type = 0;
    uart_dump_hex(buf, 4);
    STREAM_TO_UINT32(vendor_input_type, buf, remaining_bytes, return 4);
    MODEM_LOG("read_messages::vendor_input_type=0x%x, buf=0x%08x", vendor_input_type, (uint32_t)buf);
    switch (vendor_input_type)
    {
    case 0 /* ShannonInput */: ;
        uint32_t shannon_input_type = 0;
        uart_dump_hex(buf, 4);
        STREAM_TO_UINT32(shannon_input_type, buf, remaining_bytes, return 5);
        MODEM_LOG("read_messages::shannon_input_type=0x%x, buf=0x%08x", shannon_input_type, (uint32_t)buf);
        switch (shannon_input_type)
        {
        case 0 /* Sael3Input */: ;
            uint32_t seq_len = 0;
            uart_dump_hex(buf, 8);
            STREAM_TO_UINT64(seq_len, buf, remaining_bytes, return 6);
            MODEM_LOG("read_messages::seq_len=0x%x, buf=0x%08x", seq_len, (uint32_t)buf);
            for (uint32_t i = 0; i < seq_len; ++i) {
                QItemHeader header;
                STREAM_TO_QITEM_HEADER(header, buf, remaining_bytes);
                if (remaining_bytes < header.size) { return 7; }
                // if (header.msg_group == 0x3c7b) uart_dump_hex(buf, remaining_bytes);
                QItem *item = pal_MemAlloc(4, sizeof(header) + header.size, __FILE__, __LINE__);
                MODEM_LOG("sizeof(header)=0x%x, header.size=0x%x,", sizeof(header), header.size);
                MODEM_LOG("item=0x%08x, item->payload=0x%x,", item, item->payload);
                memcpy(item, (void *)&header, sizeof(header));
                memset(item->payload, 0, header.size);
                STREAM_TO_PAYLOAD(item->payload, (uint32_t)(header.size), buf, remaining_bytes);

                pal_MsgSendTo(dst_qid, item, 2);
            }
            break;

        case 1 /* NasotInput */: ;
            uint32_t msg_id = 0, obj_id = 0, input_size = 0;
            uint8_t domain_s = 0, domain_d = 0;
            uint16_t routing = 0;
            uint8_t zero[6];
            uart_dump_hex(buf, 8);
            STREAM_TO_UINT64(seq_len, buf, remaining_bytes, return 0x130);
            MODEM_LOG("read_messages::seq_len=0x%x, buf=0x%08x", seq_len, (uint32_t)buf);
            for (uint32_t i = 0; i < seq_len; ++i) {
                QItemHeader header;
                header.src_qid = 0xbb;
                header.dst_qid = 0x132;
                header.size = 10;
                header.msg_group = 0x2000;
                QItem *item = pal_MemAlloc(4, sizeof(header) + header.size, __FILE__, __LINE__);
                memcpy(item, (void *)&header, sizeof(header));
                memset(item->payload, 0, header.size);
                
                pal_MsgSendTo(header.dst_qid, item, 2);

                uint32_t *pp_session = pal_MemAlloc(4, 0xc, __FILE__, __LINE__);
                uint32_t *field_0x10 = (uint32_t *)0x50628430;
                *field_0x10 = (uint32_t)pp_session;
                pp_session[0] = (uint32_t)0x50628430;
                uint8_t * (*CreateSession)(uint32_t, uint8_t) = 0x42b47eb4 | 1;
                uint8_t *p_session = CreateSession(0x50628420, 0x13);
                pp_session[2] = (uint32_t)p_session;
                MODEM_LOG("PDU session = %p", p_session);

                STREAM_TO_UINT32(msg_id, buf, remaining_bytes, return 0x131);
                STREAM_TO_UINT32(obj_id, buf, remaining_bytes, return 0x132);
                STREAM_TO_BYTE(domain_s, buf, remaining_bytes, return 0x133);
                STREAM_TO_BYTE(domain_d, buf, remaining_bytes, return 0x134);
                STREAM_TO_UINT16(routing, buf, remaining_bytes, return 0x135);
                STREAM_TO_ARRAY(zero, buf, 6, remaining_bytes, return 0x136);
                STREAM_TO_UINT64(input_size, buf, remaining_bytes, return 0x137);
                MODEM_LOG("read_messages::input_size=0x%x", input_size);
                uint8_t *pData = (uint8_t *)pal_MemAlloc(4, input_size + 8, __FILE__, __LINE__);
                if (!pData) {
                    MODEM_LOG("ALLOC FAILED");
                    return 0x139;
                }
                STREAM_TO_ARRAY(pData + 8, buf, input_size, remaining_bytes, return 0x138);

                NrmmData *nasot_msg = (NrmmData *)pal_MemAlloc(4, sizeof(NrmmData), __FILE__, __LINE__);
                if (!nasot_msg) {
                    MODEM_LOG("ALLOC FAILED");
                    return 0x139;
                }
                nasot_msg->field_0x0.field_0x0 = msg_id;
                nasot_msg->field_0x0.field_0x4 = (msg_id >> 0xc) | obj_id;
                nasot_msg->field_0x0.field_0x8 = (msg_id >> 0x16) | obj_id;
                nasot_msg->field_0x0.field_0xc = domain_s;  // domain_s
                nasot_msg->field_0x0.domain_type = domain_d;  // domain_d
                nasot_msg->field_0x0.field_0x10 = routing;  // routing
                memset(nasot_msg->field_0x0.field_0x14, 0, 0xc);
                nasot_msg->field_0x0.field_0x20 = 4;
                nasot_msg->field_0x0.size = 0x48;
                nasot_msg->field_0x0.msg_name = "MM_RRC_DATA_IND";
                nasot_msg->pl.pData = pData + 8;
                nasot_msg->pl.dataLength = input_size;
                set_pre_state();
                uint8_t *harness = fake_test_harness();
                *harness = 1;
                fake_test(nasot_msg);
            }
            break;

        default:
            return 8;
        }
        break;
    
    default:
        return 9;
    }
    return 0;
}

error_t parse_var_list(uint8_t *p_buf, uint32_t buf_size)
{
    uint32_t num_bytes, remaining_bytes = buf_size;
    STREAM_TO_UINT32(num_bytes, p_buf, remaining_bytes, return 1);
    if (num_bytes != remaining_bytes) { return 2; }
    STREAM_TO_UINT32(vars_type, p_buf, remaining_bytes, return 3);
    switch (vars_type)
    {
    case 0 /* Observe */:
        STREAM_TO_UINT64(num_post_mem_vars, p_buf, remaining_bytes, return 4);
        if (remaining_bytes != num_post_mem_vars * sizeof (StateValue)) { return 5; }
        p_post_mem_vars = (StateValue *)p_buf;
        break;
    case 1 /* Ensure */:
        STREAM_TO_UINT64(num_pre_cond_vars, p_buf, remaining_bytes, return 4);
        if (remaining_bytes != num_pre_cond_vars * sizeof (StateValue)) { return 5; }
        p_pre_cond_vars = (StateValue *)p_buf;
        break;
    default:
        return 6;
    }
    return 0;
}

void set_single_var(uint8_t *addr, uint32_t val, uint32_t size)
{
    switch (size)
    {
    case 1:
        *addr = (uint8_t)val;
        MODEM_LOG("%p <- 0x%02x", addr, val);
        break;
    case 2:
        *(uint16_t *)addr = (uint16_t)val;
        MODEM_LOG("%p <- 0x%04x", addr, val);
        break;
    case 4:
        *(uint32_t *)addr = val;
        MODEM_LOG("%p <- 0x%08x", addr, val);
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
}

void set_pre_state()
{
    uint32_t i = 0;
    StateValue *l = p_pre_cond_vars;
    MODEM_LOG("%s: Observation list(%d):", __func__, num_pre_cond_vars);
    for (i = 0; i < num_pre_cond_vars; ++i) {
        set_single_var(l[i].addr, l[i].value, l[i].size);
    }
    return;
}

uint32_t read_single_var(uint8_t *addr, uint32_t size)
{
    uint32_t val = 0;
    switch (size)
    {
    case 1:
        val = (uint32_t)*addr;
        break;
    case 2:
        val = (uint32_t)*(uint16_t *)addr;
        break;
    case 4:
        val = *(uint32_t *)addr;
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
    return val;
}

void log_single_var(uint8_t *addr, uint32_t size)
{
    uint32_t val = read_single_var(addr, size);
    switch (size)
    {
    case 1:
        MODEM_LOG("%p = 0x%02x", addr, val);
        break;
    case 2:
        MODEM_LOG("%p = 0x%04x", addr, val);
        break;
    case 4:
        MODEM_LOG("%p = 0x%08x", addr, val);
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
}

// void log_pre_cond_vars()
// {
//     uint32_t i = 0;
//     StateValue *l = p_pre_cond_vars;

//     MODEM_LOG("%s: Observation list(%d):", __func__, num_pre_cond_vars);
//     for (i = 0; i < num_pre_cond_vars; ++i) {
//         log_single_var(l[i].addr, l[i].size);
//     }

//     return;
// }

void log_vars(StateValue *p_vars, uint32_t num_vars)
{
    uint32_t i = 0;
    MODEM_LOG("%s: Observation list(%d):", __func__, num_vars);
    for (i = 0; i < num_vars; ++i) {
        log_single_var(p_vars[i].addr, p_vars[i].size);
    }
    return;
}

void observe_vars(StateValue *p_vars, uint32_t num_vars)
{
    uint32_t i = 0;
    for (i = 0; i < num_vars; ++i) {
        p_vars[i].value = read_single_var(p_vars[i].addr, p_vars[i].size);
    }
}

error_t var_observer_setup()
{
    uint32_t buf_size;
    uint8_t *p_buf;
    error_t err;

    p_buf = getPreVariables(&buf_size);
    MODEM_LOG("pre-condition variables %d", buf_size);
    uart_dump_hex(p_buf, buf_size > 0x100 ? 0x100 : buf_size);
    err = parse_var_list(p_buf, buf_size);
    if (err != 0) {
        MODEM_LOG("Error deserializing pre-condition variables: %d", err);
        return err;
    }
    set_pre_state();

    p_buf = getVariables(&buf_size);
    MODEM_LOG("post-memory variables %d", buf_size);
    uart_dump_hex(p_buf, buf_size > 0x100 ? 0x100 : buf_size);
    err = parse_var_list(p_buf, buf_size);
    if (err != 0) {
        MODEM_LOG("Error deserializing post-memory variables: %d", err);
        return err;
    }

    return 0;
}

int fuzz_single_setup()
{
    if (sael3_qid == 0)
        sael3_qid = queuename2id("SAEL3");
    
    return 1;
}

void fuzz_single()
{
    uint32_t input_size;
    error_t err;

    MODEM_LOG("Getting variables");
    err = var_observer_setup();
    if (err != 0) {
        MODEM_LOG("Error getting variables: %d", err);
    }

    MODEM_LOG("Getting work");
    char *buf = getWork(&input_size);

    MODEM_LOG("Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);

    MODEM_LOG("Sending QItems");
    startWork(0, 0xffffffff);
    log_vars(p_pre_cond_vars, num_pre_cond_vars);
    err = send_qitems((uint8_t *)buf, input_size, sael3_qid);
    if (err != 0) {
        MODEM_LOG("Error deserializing qitems: %d", err);
    }
    log_vars(p_post_mem_vars, num_post_mem_vars);
    observe_vars(p_post_mem_vars, num_post_mem_vars);
    uint32_t c = sendVariables();
    MODEM_LOG("sendPostMemVars ret %d", c);
    doneWork(0);
}
