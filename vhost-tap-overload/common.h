#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>



/* All is little-endian */
struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1	/* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID	2	/* Csum is valid */
#define VIRTIO_NET_HDR_F_RSC_INFO	4
	uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE		0	/* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4	1	/* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP		3	/* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6	4	/* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_UDP_L4	5
#define VIRTIO_NET_HDR_GSO_ECN		0x80	/* TCP has ECN set */
	uint8_t gso_type;
	uint16_t hdr_len;		/* Ethernet + IP + tcp/udp hdrs */
	uint16_t gso_size;		/* Bytes to append to hdr_len per frame */
        uint16_t csum_start;		/* Position to start checksumming from */
	uint16_t csum_offset;		/* Offset after that to place checksum */
	uint16_t num_buffers;		/* Number of merged rx buffers */
#if 0
	uint32_t hash_value;		/* (Only if VIRTIO_NET_F_HASH_REPORT negotiated) */
	uint16_t hash_report;		/* (Only if VIRTIO_NET_F_HASH_REPORT negotiated) */
        uint16_t padding_reserved;	/* (Only if VIRTIO_NET_F_HASH_REPORT negotiated) */
#endif
};

/* The device uses this in used->flags to advise the driver: don’t kick me 
 * when you add a buffer.  It’s unreliable, so it’s simply an 
 * optimization. */
#define VIRTQ_USED_F_NO_NOTIFY  1

/* The driver uses this in avail->flags to advise the device: don't
* interrupt me when you consume a buffer. It's unreliable, so it's
* simply an optimization. */
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1


/* tap.c */

int tap_open(const char *usr_tap_name, char *new_tap_name, size_t new_tap_name_sz, uint32_t ifr_extra_flags);

int tap_set_offloads(int tap_fd);
int tap_bring_up(int tap_fd, int txqlen);
int tap_get_src_mac(int tap_fd, uint8_t src_mac[6]);


/* vhost.c */
int vhost_open();
void vhost_set_mem_table(int vhost_fd, struct iovec *iov, ssize_t iov_cnt);

struct vring_split* vring_split_new(uint16_t num, int bufs_device_readable);

void vhost_setup_vring_split(int vhost_fd, uint16_t index, struct vring_split *vring, int tap_fd);

int vring_desc_put(struct vring_split *vring, struct iovec *iov, int iov_cnt, int *id_ptr);
void vring_kick(struct vring_split *vring);

int vring_callfd(struct vring_split *vring);
int vring_errfd(struct vring_split *vring);

int vring_get_buf(struct vring_split *vring, uint8_t **buf_ptr, unsigned int *len, int *id_ptr);

int vring_recycle_id(struct vring_split *vring, int id);
void vring_print_id(struct vring_split *vring, uint32_t id);

void vring_set_suppress_notifications(struct vring_split *vring);
int vring_clear_suppress_notifications(struct vring_split *vring);
int vring_get_buf2(struct vring_split *vring, uint32_t *id_ptr, uint32_t *len_ptr);
void vring_recycle_bump(struct vring_split *vring, uint16_t d);

int vring_is_empty(struct vring_split *vring);

struct virtq_used_elem {
	uint32_t id;  /* Index of start of used descriptor chain. le32
		       * for padding reasons */
	uint32_t len; /* Total length of the descriptor chain which
		       * was written to. */
} __attribute__((packed));

int vring_get_buf_bulk(struct vring_split *vring, struct virtq_used_elem *le, int le_sz);
int vring_recycle_bulk(struct vring_split *vring, struct virtq_used_elem *le, uint16_t le_cnt);
