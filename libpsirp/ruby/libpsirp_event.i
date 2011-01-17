
typedef unsigned long uintptr_t;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef long intptr_t;

//%include <sys/event.h>

%inline %{

int psirp_rb_kqueue(void) {
    int kq;
    
    kq = kqueue();
    if (kq < 0) {
        fprintf(stderr, "kevent(): [Errno %d] %s\n", errno, strerror(errno));
    }
    
    return kq;
}

void psirp_rb_kqueue_close(int kq) {
    close(kq);
}

int psirp_rb_kevent_set(int kq, u_short flags, u_int fflags, int fd,
                        intptr_t data, void *udata) {
    static struct kevent cl[1];
    int n;
    
    EV_SET(&cl[0],       /* kevent, */
	   fd,           /* ident,  */
	   EVFILT_VNODE, /* filter, */
           flags,        /* flags,  */
	   fflags,       /* fflags, */
	   data,         /* data,   */
           udata);       /* udata   */
    
    n = kevent(kq,      /* kqueue,                */
               cl, 1,   /* *changelist, nchanges, */
               NULL, 0, /* *eventlist, nevents,   */
               NULL);   /* *timeout               */
    if (n < 0) {
        fprintf(stderr, "kevent(): [Errno %d] %s\n", errno, strerror(errno));
        return 0;
    }
    
    return 1;
}

int psirp_rb_kevent_register(int kq, psirp_pub_t pub) {
    int fd = psirp_pub_fd(pub);
    
    if (fd < 0) {
        fprintf(stderr, "psirp_pub_fd(%p): %d\n", pub, fd);
        return 0;
    }
    
    return psirp_rb_kevent_set(kq, EV_ADD | EV_CLEAR,
                               NOTE_PUBLISH | NOTE_UNMAP, fd,
                               0, pub);
}

int psirp_rb_kevent_unregister(int kq, psirp_pub_t pub) {
    int fd = psirp_pub_fd(pub);
    
    if (fd < 0) {
        fprintf(stderr, "psirp_pub_fd(%p): %d\n", pub, fd);
        return 0;
    }
    
    return psirp_rb_kevent_set(kq, EV_DELETE, NOTE_PUBLISH | NOTE_UNMAP, fd,
                               0, pub);
}

psirp_pub_t psirp_rb_kevent_listen(int kq, VALUE timeout) {
    /*
     * NOTE: Multithreaded Ruby applications should use a 0 timeout.
     *       Otherwise _all_ threads will block while one is listening.
     */
    struct timespec to, *to_p;
    static struct kevent el[1];
    int n;
    psirp_pub_t pub;
    
    if (NIL_P(timeout)) {
        to_p = NULL;
    }
    else {
        long msec = NUM2LONG(timeout);
        
        memset(&to, 0, sizeof(to));
        to_p = &to;
        
        if (msec != 0) {
            long sec = msec/1000;
            long nsec = (msec-(sec*1000))*1000000;
            
            to.tv_sec = (time_t)sec;
            to.tv_nsec = nsec;
        }
    }
    
    n = kevent(kq,      /* kqueue,                */
               NULL, 0, /* *changelist, nchanges, */
               el, 1,   /* *eventlist, nevents,   */
               to_p);   /* *timeout               */
    
    if (n > 0) {
        //printf("kevent(): %lu 0x%x 0x%x 0x%x %p %p\n",
        //       el[0].ident, el[0].filter, el[0].flags, el[0].fflags,
        //       el[0].data, el[0].udata);
        pub = (psirp_pub_t)el[0].udata;
        return pub;
    }
    else if (n == 0) {
        //fprintf(stderr, "kevent(): %d (timeout)\n", n);
    }
    else {
        fprintf(stderr, "kevent(): [Errno %d] %s\n",
                errno, strerror(errno));
    }
    
    return NULL;
}
%}
