/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "binder.h"
#include "test_server.h"

uint32_t svcmgr_lookup(struct binder_state *bs, uint32_t target, const char *name)
{
    uint32_t handle;
    unsigned iodata[512/4];
    struct binder_io msg, reply;

    bio_init(&msg, iodata, sizeof(iodata), 4);
    bio_put_uint32(&msg, 0);  // strict mode header
    bio_put_string16_x(&msg, SVC_MGR_NAME);
    bio_put_string16_x(&msg, name);

    if (binder_call(bs, &msg, &reply, target, SVC_MGR_CHECK_SERVICE))
        return 0;

    handle = bio_get_ref(&reply);

    if (handle)
        binder_acquire(bs, handle);

    binder_done(bs, &msg, &reply);

    return handle;
}

int svcmgr_publish(struct binder_state *bs, uint32_t target, const char *name, void *ptr)
{
    int status;
    unsigned iodata[512/4];
    struct binder_io msg, reply;

    bio_init(&msg, iodata, sizeof(iodata), 4);
    bio_put_uint32(&msg, 0);  // strict mode header
    bio_put_string16_x(&msg, SVC_MGR_NAME);
    bio_put_string16_x(&msg, name);
    bio_put_obj(&msg, ptr);

    if (binder_call(bs, &msg, &reply, target, SVC_MGR_ADD_SERVICE))
        return -1;

    status = bio_get_uint32(&reply);

    binder_done(bs, &msg, &reply);

    return status;
}

void sayHello(void)
{
    static int cnt = 0;
    fprintf(stderr, "say hello: %d\n", cnt++);
}


int sayHelloTo(char *name)
{
    static int cnt = 0;
    fprintf(stderr, "say hello to %s : %d\n", name, cnt++);
    return 888;
}

int hello_service_handler(struct binder_state *bs,
                   struct binder_transaction_data *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{

    /* 根据txt->code知道要调用那一个函数
     * 如果需要参数，可以从msg中取出
     * 如果需要返回结果，可以把结果放入reply
     */
    
    /* sayHello()
     * sayHello_to()
     */

    uint16_t *s;
    char name[512];
    size_t len;
    uint32_t handle;
    uint32_t strict_policy;
    int i;

    // Equivalent to Parcel::enforceInterface(), reading the RPC
    // header with the strict mode policy mask and the interface name.
    // Note that we ignore the strict_policy and don't propagate it
    // further (since we do no outbound RPCs anyway).
    strict_policy = bio_get_uint32(msg);

    switch(txn->code) {
    case HELLO_SVR_CMD_SAYHELLO:
        sayHello();
        break;
    case HELLO_SVR_CMD_SAYHELLO_TO:
        /* 从msg中取出字符串 */
        s = bio_get_string16(msg, &len);
        if(s == NULL){
            return -1;
        }
        for(i = 0; i<len; i++){
            name[i] = s[i];
        }
        name[i] = '\0';
        int res = sayHelloTo(name);
        /* 结果返回 */
        bio_put_uint32(reply, res);
        return 0;
    }
    default:
        ALOGE("unknown code %d\n", txn->code);
        return -1;
    }

    bio_put_uint32(reply, 0);
    return 0;
}

unsigned token;

int main(int argc, char **argv)
{
    struct binder_state *bs;
    uint32_t svcmgr = BINDER_SERVICE_MANAGER;
    uint32_t handle;
    int ret;

    bs = binder_open("/dev/binder", 128*1024);
    if (!bs) {
        fprintf(stderr, "failed to open binder driver\n");
        return -1;
    }

    /* add service */
    ret = svcmgr_publish(bs, svcmgr, "hello", 123);
    if (!ret) {
        fprintf(stderr, "failed to public hello service\n");
        return -1;
    }

    ret = svcmgr_publish(bs, svcmgr, "goodbye", 124);
    if (!ret) {
        fprintf(stderr, "failed to public goodbye service\n");
        return -1;
    }

#if 0
    while(1){
        /* read data */

        /* parse data */

        /* reply */
    }
#endif
    binder_loop(bs, hello_service_handler);
    return 0;
}
