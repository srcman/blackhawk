
#include <sys/param.h>
#include <libpsirp.h>

#include <string.h>
#include <stdio.h>

int create_and_publish(psirp_id_t *sid_p,
                       psirp_id_t *rid_p,
                       const char *data_str,
                       int data_str_len) {
    psirp_pub_t pub;
    void *pub_data;
    int err;
    
    err = psirp_create(data_str_len, &pub);
    if (err) {
        return err;
    }
    pub_data = psirp_pub_data(pub);
    strncpy((char *)pub_data, data_str, data_str_len);
    
    err = psirp_publish(sid_p, rid_p, pub);
    
    psirp_free(pub);
    return err;
}

int subscribe(psirp_id_t *sid_p,
              psirp_id_t *rid_p) {
    psirp_pub_t pub;
    void *pub_data;
    u_int64_t pub_data_len;
    int err;
    
    err = psirp_subscribe_sync(sid_p, rid_p, &pub, NULL);
    if (err) {
        return err;
    }
    pub_data = psirp_pub_data(pub);
    pub_data_len = psirp_pub_data_len(pub);
    
    printf("%s", (char *)pub_data);
    
    psirp_free(pub);
    return err;
}

int main(void) {
    const char sid_str[] = "12::34";
    const char rid_str[] = "56::78";
    const char data_str[] = "Hello, world!\n";
    psirp_id_t sid, rid;
    int err;
    
    psirp_atoid(&sid, sid_str);
    psirp_atoid(&rid, rid_str);
    
    printf("create and publish\n");
    err = create_and_publish(&sid, &rid, data_str, sizeof(data_str));
    if (err) {
        return err;
    }
    
    printf("subscribe\n");
    err = subscribe(&sid, &rid);
    
    return err;
}
