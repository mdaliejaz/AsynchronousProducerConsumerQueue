#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "submitjob.h"

#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int nl_bind(int pid)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = pid;

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    return 0;
}

void *receive_from_kernel(void *pid)
{
    int ret_err;
    nl_msg *message;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = *(int *)pid;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    fprintf(stdout, "Netlink Thread: Waiting for Kernel's Response Message "
        "to the posted Job.\n");

    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
    message = NLMSG_DATA(nlh);

    ret_err = message->err;
    if(ret_err < 0)
        ret_err *= -1;
    errno = ret_err;
    fprintf(stdout, "Netlink Thread: Payload from Kernel: %s", message->msg);
    if(ret_err) {
        perror("Syscall");
        fprintf(stderr, "See dmesg for more details.\n");
    }

    close(sock_fd);
    return NULL;
}
