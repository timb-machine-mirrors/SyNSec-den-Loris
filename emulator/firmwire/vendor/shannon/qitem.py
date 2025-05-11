class PALMsg:
    def __init__(self, shannon, src, dst, size, msg_id, data):
        self.src = src
        self.dst = dst
        self.size = size
        self.msg_id = msg_id
        self.data = data
        src_q = shannon.pal_queueid2name(self.src)
        self.src_name = src_q['name']
        dst_q = shannon.pal_queueid2name(self.dst)
        self.dst_name = dst_q['name']

    def __repr__(self):
        return "PALMsg<0x%04x, %s (%x) -> %s (%x), %d bytes>" % (
            self.msg_id,
            self.src_name,
            self.src,
            self.dst_name,
            self.dst,
            self.size,
        )
