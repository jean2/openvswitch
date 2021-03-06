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

#include "collectors.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket-util.h"
#include "svec.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(collectors)

struct collectors {
    int *fds;                     /* Sockets. */
    size_t n_fds;                 /* Number of sockets. */
};

/* Opens the targets specified in 'targets' for sending UDP packets.  This is
 * useful for e.g. sending NetFlow or sFlow packets.  Returns 0 if successful,
 * otherwise a positive errno value if opening at least one collector failed.
 *
 * Each target in 'targets' should be a string in the format "<host>[:<port>]".
 * <port> may be omitted if 'default_port' is nonzero, in which case it
 * defaults to 'default_port'.
 *
 * '*collectorsp' is set to a null pointer if no targets were successfully
 * added, otherwise to a new collectors object if at least one was successfully
 * added.  Thus, even on a failure return, it is possible that '*collectorsp'
 * is nonnull, and even on a successful return, it is possible that
 * '*collectorsp' is null, if 'target's is an empty svec. */
int
collectors_create(const struct svec *targets_, uint16_t default_port,
                  struct collectors **collectorsp)
{
    struct collectors *c;
    struct svec targets;
    int retval = 0;
    size_t i;

    svec_clone(&targets, targets_);
    svec_sort_unique(&targets);

    c = xmalloc(sizeof *c);
    c->fds = xmalloc(sizeof *c->fds * targets.n);
    c->n_fds = 0;
    for (i = 0; i < targets.n; i++) {
        const char *name = targets.names[i];
        int error;
        int fd;

        error = inet_open_active(SOCK_DGRAM, name, default_port, NULL, &fd);
        if (fd >= 0) {
            c->fds[c->n_fds++] = fd;
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "couldn't open connection to collector %s (%s)",
                         name, strerror(error));
            if (!retval) {
                retval = error;
            }
        }
    }
    svec_destroy(&targets);

    if (c->n_fds) {
        *collectorsp = c;
    } else {
        collectors_destroy(c);
        *collectorsp = NULL;
    }

    return retval;
}

/* Destroys 'c'. */
void
collectors_destroy(struct collectors *c)
{
    if (c) {
        size_t i;

        for (i = 0; i < c->n_fds; i++) {
            close(c->fds[i]);
        }
        free(c->fds);
        free(c);
    }
}

/* Sends the 'n'-byte 'payload' to each of the collectors in 'c'. */
void
collectors_send(const struct collectors *c, const void *payload, size_t n)
{
    if (c) {
        size_t i;

        for (i = 0; i < c->n_fds; i++) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            if (send(c->fds[i], payload, n, 0) == -1) {
                VLOG_WARN_RL(&rl, "sending to collector failed: %s",
                             strerror(errno));
            }
        }
    }
}

int
collectors_count(const struct collectors *c)
{
    return c ? c->n_fds : 0;
}
