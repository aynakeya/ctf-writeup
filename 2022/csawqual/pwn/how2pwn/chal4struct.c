#include <seccomp.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stddef.h>

int main() {
    struct sock_filter exp_filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

    struct sock_fprog exp_prog = {
        .len = sizeof(exp_filter) / sizeof(exp_filter[0]),
        .filter = exp_filter,
    };
    printf("%p\n",exp_filter[0]);
    printf("%p\n",exp_filter[1]);
    printf("%p\n",exp_filter[2]);
    printf("%p\n",exp_filter[3]);

    printf("%p\n",SECCOMP_IOCTL_NOTIF_RECV);
    printf("%p\n",SECCOMP_IOCTL_NOTIF_SEND);

    printf("fork %x\n",__NR_fork);
}