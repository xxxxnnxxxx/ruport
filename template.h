#ifndef _TEMPLATE_H_
#define _TEMPLATE_H_

struct kvpair {
    char name[200];
    char value[200];
};

#define Segment_Attr_Normal 0x01    // 没有数据的任何处理的
#define Segment_Attr_Optional 0x02  // 可选参数
#define Segmetn_Attr_Required 0x03    // 

struct segment {
    int size;
    char *pbuf;
    int attr;
    struct segment *pre;
    struct segment *next;
};

static __inline void init_seg_header(struct segment *header) {
    if (header == 0)
        return;

    header->pre = 0;
    header->next= 0;
}

// 向segment节点插入
static __inline void insert_seg(struct segment *header, struct segment *node) {
    if (header == 0)
        return;

    struct segment *p = header;
    while(1) {
        if(p->next == 0){
            p->next = node;
            node->pre =p;
            break;
        }
        
        p = p->next;
    }
    return;
}
// 删除一个节点
static __inline void delete_seg(struct segment *header, struct segment *node) {
    return;
}

int parse_template(const char *temp, struct kvpair *kvs, int count);


#endif