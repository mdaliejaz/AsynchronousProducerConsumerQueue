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

void receive_from_kernel(int pid)
{
    char *str1, str2[10], *junk;
    int ret_err;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = pid;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Waiting for Kernel's Response Message to the posted Job.\n");

    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
    printf("Received following Message Payload from Kernel: \n%s", (char *)NLMSG_DATA(nlh));

    str1 = strstr((char *)NLMSG_DATA(nlh), "(Return Code = ");
    if(str1 != NULL) {
        memcpy(str2, &str1[strlen(str1)-5], 4);
        str2[4] = '\0';
        ret_err = strtol(str2, &junk, 10);
        if(ret_err < 0)
            ret_err *= -1;
        errno = ret_err;
        perror("Reason");
        printf("See dmesg for more details.\n");
    }

    close(sock_fd);
}
