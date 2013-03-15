/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "hash.h"
#include "leak-checker.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "shash.h"
#include "vconn-provider.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vconn_udp)

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

struct pvconn_pudp
{
    struct pvconn pvconn;
    int fd;
    struct hmap slaves;   /* All accepted UDP "connections" */
};

struct vconn_udp
{
    struct vconn vconn;
    struct pvconn_pudp *master;
    struct hmap_node hmap_node;  /* In "master" map. */
    int fd;                      /* This may belong to "master" */
};

/* Active UDP socket vconn. */

// Need to use IP_MTU_DISCOVER to force IP fragmentation
// setsockopt

struct vconn_class udp_vconn_class;

static struct vconn_udp *
vconn_udp_cast(struct vconn *vconn)
{
    return CONTAINER_OF(vconn, struct vconn_udp, vconn);
}

static int
vconn_udp_new(const char *name, struct pvconn_pudp *master, int fd,
		 int connect_status, const struct sockaddr_in *remote,
		 struct vconn **vconnp)
{
    struct vconn_udp *s;
    struct sockaddr_in local;
    socklen_t local_len = sizeof local;
    int retval;

    s = xzalloc(sizeof *s);
    vconn_init(&s->vconn, &udp_vconn_class, connect_status, name);

    if (master != NULL) {
        s->master = master;
        hmap_insert(&master->slaves, &s->hmap_node, hash_string(name, 0));
        s->fd = master->fd;
    } else {
        /* Disable MTU discovery to force IP fragmentation. Yuck ! */
        int mtu_type = IP_PMTUDISC_DONT;
	setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type));
        s->fd = fd;
    }

    /* Get the local IP and port information */
    retval = getsockname(s->fd, (struct sockaddr *)&local, &local_len);
    if (retval) {
        memset(&local, 0, sizeof local);
    }

    s->vconn.remote_ip = remote->sin_addr.s_addr;
    s->vconn.remote_port = remote->sin_port;
    s->vconn.local_ip = local.sin_addr.s_addr;
    s->vconn.local_port = local.sin_port;

    *vconnp = &s->vconn;
    return 0;
}

/* Creates a new vconn that will send and receive data on a udp socket
 * named 'name' and stores a pointer to the vconn in '*vconnp'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
vconn_udp_open(const char *name, char *suffix, struct vconn **vconnp)
{
    struct sockaddr_in sin;
    int fd, error;

    error = inet_open_active(SOCK_DGRAM, suffix, 0, &sin, &fd);
    if (fd >= 0) {
        return vconn_udp_new(name, NULL, fd, error, &sin, vconnp);
    } else {
        VLOG_ERR("%s: connect: %s", name, strerror(error));
        return error;
    }
}

static void
vconn_udp_close(struct vconn *vconn)
{
    struct vconn_udp *s = vconn_udp_cast(vconn);

    if(s->master != NULL) {
        hmap_remove(&s->master->slaves, &s->hmap_node);
    } else {
        close(s->fd);
    }

    free(s);
}

static int
vconn_udp_connect(struct vconn *vconn)
{
    struct vconn_udp *s = vconn_udp_cast(vconn);
    return check_connection_completion(s->fd);
}

static int
vconn_udp_recv(struct vconn *vconn, struct ofpbuf **bufferp)
{
    struct vconn_udp *s = vconn_udp_cast(vconn);
    struct sockaddr_in sin; 
    socklen_t sin_len = sizeof sin;
    ssize_t retval;
    char *buffer[4];
    struct ofpbuf *rxbuf;
    int rx_len;

    /* Only peek at the socket, don't read any data.
     * Get sender address. */
    retval = recvfrom(s->fd, buffer, 4, MSG_DONTWAIT | MSG_PEEK,
		      (struct sockaddr *) &sin, &sin_len);
    if (retval < 0) {
        return errno;
    }
    if (retval == 0) {
        return EAGAIN;
    }

    if (sin_len != sizeof(struct sockaddr_in) || sin.sin_family != AF_INET) {
        return EPROTO;
    }

    /* We may share the socket with "master" */
    if((sin.sin_addr.s_addr != s->vconn.remote_ip)
       || (sin.sin_port != s->vconn.remote_port)) {
        return EAGAIN;
    }

    /* Get message size */
    retval = ioctl(s->fd, FIONREAD, &rx_len);
    if (retval < 0) {
        return errno;
    }
    if (rx_len <= 0) {
        return EAGAIN;
    }

    /* Allocate new receive buffer with packet size. */
    rxbuf = ofpbuf_new(rx_len);

    retval = recvfrom(s->fd, ofpbuf_tail(rxbuf), rx_len, MSG_DONTWAIT,
		      (struct sockaddr *) &sin, &sin_len);
    if (retval < 0) {
        ofpbuf_delete(rxbuf);
        return errno;
    }

    rxbuf->size += retval;
    *bufferp = rxbuf;
    return 0;
}

static int
vconn_udp_send(struct vconn *vconn, struct ofpbuf *buffer)
{
    struct vconn_udp *s = vconn_udp_cast(vconn);
    ssize_t retval;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = s->vconn.remote_ip;
    sin.sin_port = s->vconn.remote_port;
 
    retval = sendto(s->fd, buffer->data, buffer->size, MSG_DONTWAIT,
		    (struct sockaddr *) &sin, sizeof sin);

    /* Should get EMSGSIZE if short write */
    return (retval > 0 ? 0
            : retval == 0 ? EAGAIN
            : errno);
}

static void
vconn_udp_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct vconn_udp *s = vconn_udp_cast(vconn);
    switch (wait) {
    case WAIT_CONNECT:
    case WAIT_SEND:
        poll_fd_wait(s->fd, POLLOUT);
        break;

    case WAIT_RECV:
        /* Master will poll */
        /*poll_fd_wait(s->fd, POLLIN);*/
        break;

    default:
        NOT_REACHED();
    }
}

struct vconn_class udp_vconn_class = {
    "udp",
    vconn_udp_open,
    vconn_udp_close,
    vconn_udp_connect,
    vconn_udp_recv,
    vconn_udp_send,
    NULL,                       /* run */
    NULL,                       /* run_wait */
    vconn_udp_wait,
};

/* Passive udp socket vconn. */

struct pvconn_class pudp_pvconn_class;

static struct pvconn_pudp *
pvconn_pudp_cast(struct pvconn *pvconn)
{
    return CONTAINER_OF(pvconn, struct pvconn_pudp, pvconn);
}

/* Creates a new pvconn named 'name' that will accept new connections using
 * pudp_accept() and stores a pointer to the pvconn in '*pvconnp'.
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
static int
pvconn_pudp_listen(const char *name, char *suffix,
		   struct pvconn **pvconnp)
{
    struct pvconn_pudp *ps;
    struct sockaddr_in sin;
    char bound_name[128];
    int fd;
    int mtu_type;

    /* Grab code from stream_open_with_default_ports() to handle
     * no port specified... */

    fd = inet_open_passive(SOCK_DGRAM, suffix, -1, &sin);
    if (fd < 0) {
        return -fd;
    }

    /* Disable MTU discovery to force IP fragmentation. Yuck ! */
    mtu_type = IP_PMTUDISC_DONT;
    setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type));

    sprintf(bound_name, "pudp:%"PRIu16":"IP_FMT,
            ntohs(sin.sin_port), IP_ARGS(&sin.sin_addr.s_addr));

    ps = xzalloc(sizeof *ps);
    pvconn_init(&ps->pvconn, &pudp_pvconn_class, bound_name);
    ps->fd = fd;
    hmap_init(&ps->slaves);
    *pvconnp = &ps->pvconn;

    return 0;
}

static void
pvconn_pudp_close(struct pvconn *pvconn)
{
    struct pvconn_pudp *ps = pvconn_pudp_cast(pvconn);
    struct vconn_udp *slave, *next_slave;

    close(ps->fd);

    HMAP_FOR_EACH_SAFE (slave, next_slave, struct vconn_udp, hmap_node,
                        &ps->slaves) {
        vconn_udp_close(&slave->vconn);
    }
    hmap_destroy(&ps->slaves);
    free(ps);
}

static int
pvconn_pudp_accept(struct pvconn *pvconn, struct vconn **new_vconnp)
{
    struct pvconn_pudp *ps = pvconn_pudp_cast(pvconn);
    struct sockaddr_in sin; 
    socklen_t sin_len = sizeof sin;
    int retval;
    char buffer[4];
    char name[128];
    char *master_name;
    struct vconn_udp *slave;

    /* Only peek at the socket, don't read any data. Get sender address */
    retval = recvfrom(ps->fd, buffer, 4, MSG_DONTWAIT | MSG_PEEK,
		      (struct sockaddr *) &sin, &sin_len);
    if (retval < 0) {
        retval = errno;
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&rl, "accept: %s", strerror(retval));
        }
        return retval;
    }

    if (sin_len != sizeof(struct sockaddr_in) || sin.sin_family != AF_INET) {
        VLOG_DBG_RL(&rl, "accept: %s", strerror(retval));
        return EPROTO;
    }

    master_name = pvconn_get_name(pvconn);
    sprintf(name, "udp:"IP_FMT":%"PRIu16,
	    IP_ARGS(&sin.sin_addr), ntohs(sin.sin_port));

    HMAP_FOR_EACH_WITH_HASH (slave, struct vconn_udp, hmap_node,
                             hash_string(name, 0), &ps->slaves) {
        if (!strcmp(vconn_get_name(&slave->vconn), name)) {
	    /* udp vconn will deal with it */
            return EAGAIN;
        }
    }

    return vconn_udp_new(name, ps, 0, 0, &sin, new_vconnp);
}

static void
pvconn_pudp_wait(struct pvconn *pvconn)
{
    struct pvconn_pudp *ps = pvconn_pudp_cast(pvconn);
    poll_fd_wait(ps->fd, POLLIN);
}

struct pvconn_class pudp_pvconn_class = {
    "pudp",
    pvconn_pudp_listen,
    pvconn_pudp_close,
    pvconn_pudp_accept,
    pvconn_pudp_wait
};

