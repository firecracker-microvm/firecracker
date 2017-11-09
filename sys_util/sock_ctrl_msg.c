// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <string.h> // memcpy
#include <unistd.h> // close
#include <sys/errno.h>
#include <sys/socket.h> // CMSG_*

/*
 * Returns the number of bytes the `cmsg_buffer` must be for the functions that take a cmsg_buffer
 * in this module.
 * Arguments:
 *    * `fd_count` - Maximum number of file descriptors to be sent or received via the cmsg.
 */
size_t scm_cmsg_buffer_len(size_t fd_count)
{
    return CMSG_SPACE(sizeof(int) * fd_count);
}

/*
 * Convenience wrapper around `sendmsg` that builds up the `msghdr` structure for you given the
 * array of fds.
 * Arguments:
 *   * `fd` - Unix domain socket to `sendmsg` on.
 *   * `outv` - Array of `outv_count` length `iovec`s that contain the data to send.
 *   * `outv_count` - Number of elements in `outv` array.
 *   * `cmsg_buffer` - A buffer that must be at least `scm_cmsg_buffer_len(fd_count)` bytes long.
 *   * `fds` - Array of `fd_count` file descriptors to send along with data.
 *   * `fd_count` - Number of elements in `fds` array.
 * Returns:
 * A non-negative number indicating how many bytes were sent on success or a negative errno on
 * failure.
 */
ssize_t scm_sendmsg(int fd, const struct iovec *outv, size_t outv_count, uint8_t *cmsg_buffer,
                    const int *fds, size_t fd_count)
{
    if (fd < 0 || ((!cmsg_buffer || !fds) && fd_count > 0))
        return -EINVAL;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = (struct iovec *)outv; // discard const, sendmsg won't mutate it
    msg.msg_iovlen = outv_count;

    if (fd_count) {
        msg.msg_control = cmsg_buffer;
        msg.msg_controllen = scm_cmsg_buffer_len(fd_count);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, fd_count * sizeof(int));

        msg.msg_controllen = cmsg->cmsg_len;
    }

    ssize_t bytes_sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    if (bytes_sent == -1)
        return -errno;

    return bytes_sent;
}

/*
 * Convenience wrapper around `recvmsg` that builds up the `msghdr` structure and returns up to
 * `*fd_count` file descriptors in the given `fds` array.
 * Arguments:
 *   * `fd` - Unix domain socket to `recvmsg` on.
 *   * `outv` - Array of `outv_count` length `iovec`s that will contain the received data.
 *   * `outv_count` - Number of elements in `outv` array.
 *   * `cmsg_buffer` - A buffer that must be at least `scm_cmsg_buffer_len(*fd_count)` bytes long.
 *   * `fds` - Array of `fd_count` file descriptors to receive along with data.
 *   * `fd_count` - Number of elements in `fds` array.
 * Returns:
 * A non-negative number indicating how many bytes were received on success or a negative errno on
 * failure.
 */
ssize_t scm_recvmsg(int fd, struct iovec *outv, size_t outv_count, uint8_t *cmsg_buffer, int *fds,
                    size_t *fd_count)
{
    if (fd < 0 || !cmsg_buffer || !fds || !fd_count)
        return -EINVAL;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = outv;
    msg.msg_iovlen = outv_count;
    msg.msg_control = cmsg_buffer;
    msg.msg_controllen = scm_cmsg_buffer_len(*fd_count);

    ssize_t total_read = recvmsg(fd, &msg, 0);
    if (total_read == -1)
        return -errno;

    if (total_read == 0 && CMSG_FIRSTHDR(&msg) == NULL) {
        *fd_count = 0;
        return  0;
    }

    size_t fd_idx = 0;
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
            continue;

        size_t cmsg_fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

        int *cmsg_fds = (int *)CMSG_DATA(cmsg);
        size_t cmsg_fd_idx;
        for (cmsg_fd_idx = 0; cmsg_fd_idx < cmsg_fd_count; cmsg_fd_idx++) {
            if (fd_idx < *fd_count) {
                fds[fd_idx] = cmsg_fds[cmsg_fd_idx];
                fd_idx++;
            } else {
                close(cmsg_fds[cmsg_fd_idx]);
            }
        }
    }

    *fd_count = fd_idx;

    return total_read;
}
