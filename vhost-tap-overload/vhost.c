#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/vhost.h>

#include "common.h"

#ifndef VIRTIO_NET_F_MRG_RXBUF
#define VIRTIO_NET_F_MRG_RXBUF 15
#endif
#ifndef VIRTIO_F_RING_RESET
#define VIRTIO_F_RING_RESET 40
#endif

#define DO_EVENT_IDX 1

int vhost_open()
{
	int vhost_fd = open("/dev/vhost-net", O_RDWR);
	if (vhost_fd < 0) {
		error(-1, errno, "open(/dev/vhost-net)");
	}

	/* Set current process as the (exclusive) owner of this file
	 * descriptor.  This must be called before any other vhost
	 * command.  Further calls to VHOST_OWNER_SET fail until
	 * VHOST_OWNER_RESET is called. */
	int r = ioctl(vhost_fd, VHOST_SET_OWNER, NULL);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_OWNER)");
	}

	uint64_t features = 0;
	r = ioctl(vhost_fd, VHOST_GET_FEATURES, &features);
	if (r < 0) {
		error(-1, errno, "ioctl(VHOST_GET_FEATURES)");
	}

	uint64_t known_features = 0;

#define PRINT_FEATURE(f)                                                                 \
	if (features & (1ULL << f)) {                                                    \
		known_features |= 1ULL << f;                                             \
		printf(" " #f);                                                          \
	}

	printf("Vhost features: ");

	PRINT_FEATURE(VIRTIO_F_NOTIFY_ON_EMPTY);
	PRINT_FEATURE(VIRTIO_RING_F_INDIRECT_DESC);
	PRINT_FEATURE(VIRTIO_RING_F_EVENT_IDX);
	PRINT_FEATURE(VHOST_F_LOG_ALL);
	PRINT_FEATURE(VIRTIO_F_ANY_LAYOUT);
	PRINT_FEATURE(VIRTIO_F_VERSION_1);

	PRINT_FEATURE(VHOST_NET_F_VIRTIO_NET_HDR);
	PRINT_FEATURE(VIRTIO_NET_F_MRG_RXBUF);
	PRINT_FEATURE(VIRTIO_F_ACCESS_PLATFORM);
	PRINT_FEATURE(VIRTIO_F_RING_RESET);

	if (~known_features & features) {
		printf(" UNKNOWN:0x%lx", ~known_features & features);
	}
	printf("\n");

	uint64_t our_features = (0
				 //		| (1ULL << VIRTIO_RING_F_INDIRECT_DESC)
				 | (1ULL << VIRTIO_F_VERSION_1)
				 //		| (1ULL << VIRTIO_F_ACCESS_PLATFORM)
				 //		| (1ULL << VHOST_NET_F_VIRTIO_NET_HDR)
				 //		| (1ULL << VIRTIO_F_ANY_LAYOUT)
	);

	if (DO_EVENT_IDX) {
		our_features |= (1ULL << VIRTIO_RING_F_EVENT_IDX);
	} else {
		our_features |= (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY);
	}

	r = ioctl(vhost_fd, VHOST_SET_FEATURES, &our_features);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_FEATURES)");
	}

	features = 0;
	r = ioctl(vhost_fd, VHOST_GET_BACKEND_FEATURES, &features);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_GET_BACKEND_FEATURES)");
	}

	printf("Vhost backend features: ");

	PRINT_FEATURE(VHOST_BACKEND_F_IOTLB_MSG_V2);
	PRINT_FEATURE(VHOST_BACKEND_F_IOTLB_BATCH);
	if (~known_features & features) {
		printf(" UNKNOWN:0x%lx", ~known_features & features);
	}
	printf("\n");

	our_features = 0;
	r = ioctl(vhost_fd, VHOST_SET_BACKEND_FEATURES, &our_features);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_BACKEND_FEATURES)");
	}

	return vhost_fd;
}

void vhost_set_mem_table(int vhost_fd, struct iovec *iov, ssize_t iov_cnt)
{
	struct vhost_memory *mem =
		calloc(1, sizeof(struct vhost_memory) +
				  sizeof(struct vhost_memory_region) * iov_cnt);
	mem->nregions = iov_cnt;
	int i;
	for (i = 0; i < iov_cnt; i++) {
		mem->regions[i].guest_phys_addr =
			(uint64_t)(unsigned long)iov[i].iov_base;
		mem->regions[i].userspace_addr = (uint64_t)(unsigned long)iov[i].iov_base;
		mem->regions[i].memory_size = iov[i].iov_len;
	}
	int r = ioctl(vhost_fd, VHOST_SET_MEM_TABLE, mem);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_MEM_TABLE)");
	}
}

/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define VIRTQ_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT 4

/* Little-endian */
struct virtq_desc {
	uint64_t addr;	/* Address (guest-physical). */
	uint32_t len;	/* Length. */
	uint16_t flags; /* The flags as indicated above. */
	uint16_t next;	/* We chain unused descriptors via this, too */
} __attribute__((packed));

/* Little-endian */
struct virtq_avail {
	volatile uint16_t flags;
	volatile uint16_t idx;
	uint16_t ring[];
	/* Only if VIRTIO_F_EVENT_IDX: le16 used_event; */
} __attribute__((packed));

/* struct virtq_used_elem { */
/* 	uint32_t id;  /\* Index of start of used descriptor chain. le32 */
/* 		       * for padding reasons *\/ */
/* 	uint32_t len; /\* Total length of the descriptor chain which */
/* 		       * was written to. *\/ */
/* } __attribute__((packed)); */

struct virtq_used {
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[];
	/* Only if VIRTIO_F_EVENT_IDX: le16 avail_event; */
} __attribute__((packed));

struct vring_split {
	uint32_t num;

	struct virtq_desc *desc;
	struct virtq_avail *avail;
	uint16_t *used_event_ptr;
	struct virtq_used *used;
	uint16_t *avail_event_ptr;

	int kick;
	int call;
	int errfd;

	uint16_t avail_idx_shadow;

	uint32_t desc_free_head;
	int desc_num_free;

	uint16_t desc_flags;

	uint16_t used_idx_last;
};

void vring_print_id(struct vring_split *vring, uint32_t id)
{
	/* printf("used %d %d\n", vring->used->idx, *vring->used_event_ptr); */
	/* printf("avail %d %d\n", vring->avail->idx, *vring->avail_event_ptr); */
	/* return; */
	printf("id=%d %p %d %d %d\n", id, (void *)vring->desc[id].addr,
	       vring->desc[id].len, vring->desc[id].flags, vring->desc[id].next);
}

struct vring_split *vring_split_new(uint16_t num, int bufs_device_readable)
{
	struct vring_split *vring = calloc(1, sizeof(struct vring_split));
	int r = 0;
	r |= posix_memalign((void **)&vring->desc, 16, sizeof(struct virtq_desc) * num);
	r |= posix_memalign((void **)&vring->avail, 8,
			    sizeof(struct virtq_avail) + sizeof(uint16_t) * num +
				    sizeof(uint16_t));
	r |= posix_memalign((void **)&vring->used, 8,
			    sizeof(struct virtq_used) +
				    sizeof(struct virtq_used_elem) * num +
				    sizeof(uint16_t));
	if (r) {
		error(-1, errno, "posix_memalign()");
	}

	memset(vring->desc, 0, sizeof(struct virtq_desc) * num);
	memset(vring->avail, 0,
	       sizeof(struct virtq_avail) + sizeof(uint16_t) * num + sizeof(uint16_t));
	vring->used_event_ptr = (void*)((uint8_t *)vring->avail + sizeof(struct virtq_avail) +
					    sizeof(uint16_t) * num);
	memset(vring->used, 0,
	       sizeof(struct virtq_used) + sizeof(struct virtq_used_elem) * num +
		       sizeof(uint16_t));
	vring->avail_event_ptr = (void*)((uint8_t *)vring->used + sizeof(struct virtq_used) +
					 sizeof(struct virtq_used_elem) * num);
	vring->num = num;
	//*vring->used_event_ptr +=1;

	vring->kick = eventfd(0, EFD_NONBLOCK);
	vring->call = eventfd(0, EFD_NONBLOCK);
	vring->errfd = eventfd(0, EFD_NONBLOCK);

	vring->desc_num_free = num;
	vring->desc_flags = bufs_device_readable ? 0 : VIRTQ_DESC_F_WRITE;

	if (0) {
		uint16_t a = 1;
		write(vring->call, &a, 8);
	}
	return vring;
}

void vhost_setup_vring_split(int vhost_fd, uint16_t index, struct vring_split *vring,
			     int tap_fd)
{
	int r = ioctl(vhost_fd, VHOST_SET_VRING_NUM,
		      &(struct vhost_vring_state){.index = index, .num = vring->num});
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_VRING_NUM)");
	}
	r = ioctl(vhost_fd, VHOST_SET_VRING_KICK,
		  &(struct vhost_vring_file){.index = index, .fd = vring->kick});
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_VRING_KICK)");
	}
	r = ioctl(vhost_fd, VHOST_SET_VRING_CALL,
		  &(struct vhost_vring_file){.index = index, .fd = vring->call});
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_VRING_CALL)");
	}

	r = ioctl(vhost_fd, VHOST_SET_VRING_ERR,
		  &(struct vhost_vring_file){.index = index, .fd = vring->errfd});
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_VRING_ERR)");
	}

	/* on x86-32 pointers are signed, so you must first convert
	 * them to unsigned before bringing up to 64 bits to avoid
	 * sign extension */
	struct vhost_vring_addr addr = {
		.index = index,
		.desc_user_addr = (uint64_t)(unsigned long)vring->desc,
		.avail_user_addr = (uint64_t)(unsigned long)vring->avail,
		.used_user_addr = (uint64_t)(unsigned long)vring->used,
	};

	r = ioctl(vhost_fd, VHOST_SET_VRING_ADDR, &addr);
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_SET_VRING_ADDR)");
	}

	r = ioctl(vhost_fd, VHOST_NET_SET_BACKEND,
		  &(struct vhost_vring_file){.index = index, .fd = tap_fd});
	if (r != 0) {
		error(-1, errno, "ioctl(VHOST_NET_SET_BACKEND)");
	}
}

typedef __u8 __attribute__((__may_alias__)) __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1:
		*(__u8_alias_t *)res = *(volatile __u8_alias_t *)p;
		break;
	case 2:
		*(__u16_alias_t *)res = *(volatile __u16_alias_t *)p;
		break;
	case 4:
		*(__u32_alias_t *)res = *(volatile __u32_alias_t *)p;
		break;
	case 8:
		*(__u64_alias_t *)res = *(volatile __u64_alias_t *)p;
		break;
	default:
		asm volatile("" : : : "memory");
		__builtin_memcpy((void *)res, (const void *)p, size);
		asm volatile("" : : : "memory");
	}
}
#define READ_ONCE(x)                                                                     \
	({                                                                               \
		union {                                                                  \
			typeof(x) __val;                                                 \
			char __c[1];                                                     \
		} __u = {.__c = {0}};                                                    \
		__read_once_size(&(x), __u.__c, sizeof(x));                              \
		__u.__val;                                                               \
	})

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1:
		*(volatile __u8_alias_t *)p = *(__u8_alias_t *)res;
		break;
	case 2:
		*(volatile __u16_alias_t *)p = *(__u16_alias_t *)res;
		break;
	case 4:
		*(volatile __u32_alias_t *)p = *(__u32_alias_t *)res;
		break;
	case 8:
		*(volatile __u64_alias_t *)p = *(__u64_alias_t *)res;
		break;
	default:
		asm volatile("" : : : "memory");
		__builtin_memcpy((void *)p, (const void *)res, size);
		asm volatile("" : : : "memory");
	}
}
#define WRITE_ONCE(x, val)                                                               \
	({                                                                               \
		union {                                                                  \
			typeof(x) __val;                                                 \
			char __c[1];                                                     \
		} __u = {.__val = (val)};                                                \
		__write_once_size(&(x), __u.__c, sizeof(x));                             \
		__u.__val;                                                               \
	})
int vring_desc_put(struct vring_split *vring, struct iovec *iov, int iov_cnt, int *id_ptr)
{
	if (vring->desc_num_free < iov_cnt) {
		return ENOMEM;
	}

	//*vring->used_event_ptr +=1;

	vring->desc_num_free -= iov_cnt;

	uint16_t flags = vring->desc_flags;

	uint32_t first = vring->desc_free_head;

	int i;
	for (i = 0; i < iov_cnt; i++) {
		int this_idx = vring->desc_free_head;

		int last = i == iov_cnt - 1;
		struct iovec *io = &iov[i];
		vring->desc[this_idx % vring->num] = (struct virtq_desc){
			.addr = (uint64_t)(unsigned long)io->iov_base,
			.len = io->iov_len,
			.flags = flags | (last ? 0 : VIRTQ_DESC_F_NEXT),
			.next = last ? 0 : ((this_idx + 1) % vring->num),
		};
		vring->desc_free_head += 1;
	}
	// wmb();
	asm volatile("" ::: "memory");
	*id_ptr = first;

	vring->avail->ring[vring->avail_idx_shadow % vring->num] = first % vring->num;
	vring->avail_idx_shadow += 1;
	__asm__ __volatile__("" : : : "memory");
	vring->avail->idx = vring->avail_idx_shadow;
	__asm__ __volatile__("" : : : "memory");

	//int needs_kick = !(vring->used->flags & VIRTQ_USED_F_NO_NOTIFY);
	return 1; // needs_kick;
}

int vring_recycle_id(struct vring_split *vring, int id)
{

	vring->avail->ring[vring->avail_idx_shadow % vring->num] = id % vring->num;
	vring->avail_idx_shadow += 1;
	__asm__ __volatile__("" : : : "memory");
	vring->avail->idx = vring->avail_idx_shadow;
	__asm__ __volatile__("" : : : "memory");

	int needs_kick;
	if (DO_EVENT_IDX == 0) {
		needs_kick = !(READ_ONCE(vring->used->flags) & VIRTQ_USED_F_NO_NOTIFY);
	} else {
		needs_kick = (vring->avail_idx_shadow - 1) == *vring->avail_event_ptr;
	}
	return needs_kick;
}

void vring_recycle_bump(struct vring_split *vring, uint16_t d)
{
	__asm__ __volatile__("" : : : "memory");
	*vring->used_event_ptr += d;
}

void vring_kick(struct vring_split *vring, int cnt)
{
	if (cnt == -1) {
		printf("used: %5d/%5d/%5d avail: %5d/%5d/%5d ",
		       vring->used_idx_last,
		       vring->used->idx,
		       *vring->avail_event_ptr,
		       vring->avail_idx_shadow,
		       vring->avail->idx,
		       *vring->used_event_ptr
			);
		return;
	}
	uint64_t v = 1;
	write(vring->kick, &v, sizeof(v));
}

int vring_callfd(struct vring_split *vring) { return vring->call; }

int vring_errfd(struct vring_split *vring) { return vring->errfd; }


void vring_set_suppress_notifications(struct vring_split *vring)
{
	if (DO_EVENT_IDX) return ;
	/* printf("used %d %d\n", vring->used->idx, *vring->used_event_ptr); */
	/* printf("avail %d %d\n", vring->avail->idx, *vring->avail_event_ptr); */
	uint32_t flags = READ_ONCE(vring->avail->flags);
	WRITE_ONCE(vring->avail->flags, flags | VIRTQ_AVAIL_F_NO_INTERRUPT);
}

int vring_clear_suppress_notifications(struct vring_split *vring)
{
	if (DO_EVENT_IDX) return 0;
	/* printf("used %d %d\n", vring->used->idx, *vring->used_event_ptr); */
	uint32_t flags = READ_ONCE(vring->avail->flags);
	int old = !!(flags & VIRTQ_AVAIL_F_NO_INTERRUPT);
	WRITE_ONCE(vring->avail->flags, flags & ~VIRTQ_AVAIL_F_NO_INTERRUPT);
	return old;
}

int vring_get_buf2(struct vring_split *vring, uint32_t *id_ptr, uint32_t *len_ptr)
{
	if (vring->used_idx_last != vring->used->idx) {
		/* if (DO_EVENT_IDX != 0) { */
		/* 	*vring->used_event_ptr += 1; */
		/* 	__asm__ __volatile__("" : : : "memory"); */
		/* } */
		// barrier
		asm volatile("" ::: "memory");
		struct virtq_used_elem e =
			vring->used->ring[vring->used_idx_last % vring->num];
		vring->used_idx_last += 1;
		*id_ptr = e.id;
		*len_ptr = e.len;
		return 1;
	}

	return 0;
}

int vring_is_empty(struct vring_split *vring)
{
	return vring->used_idx_last == READ_ONCE(vring->used->idx);
}

int vring_get_buf_bulk(struct vring_split *vring, struct virtq_used_elem *le, int le_sz)
{
	int i;
	for(i=0; i < le_sz; i++) {
		if (vring->used_idx_last == READ_ONCE(vring->used->idx))
			break;
		asm volatile("" ::: "memory");
		le[i] = vring->used->ring[vring->used_idx_last % vring->num];
		vring->used_idx_last += 1;
	}
	return i;
}

int vring_recycle_bulk(struct vring_split *vring, struct virtq_used_elem *le, uint16_t le_cnt)
{
	vring_recycle_bump(vring, le_cnt);
	__asm__ __volatile__("" : : : "memory");

	int needs_kick = 0;
	for (int i=0; i<le_cnt; i++) {
		vring->avail->ring[vring->avail_idx_shadow % vring->num] = le[i].id % vring->num;
		vring->avail_idx_shadow += 1;
		__asm__ __volatile__("" : : : "memory");
		WRITE_ONCE(vring->avail->idx, vring->avail_idx_shadow);

		if (DO_EVENT_IDX == 0) {
			needs_kick |= !(READ_ONCE(vring->used->flags) & VIRTQ_USED_F_NO_NOTIFY);
		} else {
			needs_kick |= (vring->avail_idx_shadow - 1) == READ_ONCE(*vring->avail_event_ptr);
		}
	}

	return needs_kick;
}


/*

  int vring_get_buf(struct vring_split *vring, uint8_t **buf_ptr, unsigned int *len_ptr,
		  int *id_ptr)
{
//	printf("used_flag:%d used_idx_last:%d used_idx:%d\n",
//	       vring->used->flags,
//	       vring->used_idx_last, vring->used->idx);
	// rmb
	asm volatile("" ::: "memory");
	uint32_t used_idx = READ_ONCE(vring->used->idx);
	// printf("%d %d\n",vring->used_idx_last,used_idx);
	if (vring->used_idx_last != used_idx) {
		asm volatile("" ::: "memory");
		// We're at the mercy of the other side and could overflow.
		struct virtq_used_elem e =
			vring->used->ring[vring->used_idx_last % vring->num];
		vring->used_idx_last += 1;
		*len_ptr = e.len;
		*buf_ptr = (uint8_t *)vring->desc[e.id % vring->num].addr;
		*id_ptr = e.id;
		vring->desc_num_free += 1;
		return 1;
	}

	return 0;
}
*/

/*
  used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

used: idx_last 65535 idx 65535 event 65535 avail: idx_sha 511 idx 511 event 255 rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

*rx* used: 48422/48422/47746 avail: 48677/48677/48422 *tx* used: 65535/65535/65535 avail:   511/  511/  255  | rx=0.000 kpps / -nanppw  tx=0.000 kpps / -nanppw

*/
