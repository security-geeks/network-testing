#include <linux/if_tun.h>
#include <errno.h>
#include <sys/epoll.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/inet.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>

#include "common.h"

uint64_t realtime_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int hex_dump(char *desc, void *addr, int len)
{
	const char hex[] = "0123456789abcdef";
	int i, lines = 0;
	char line[128];
	memset(line, ' ', 128);
	uint8_t *pc = (uint8_t *)addr;

	if (desc != NULL) {
		printf("%s:\n", desc);
	}

	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0) {
				printf("%.*s\n", 128, line);
				lines++;
			}
			snprintf(line, 128, "  0x%04x: ", i);
		}

		line[10 + (i % 16) * 3 + 0] = hex[(pc[i] >> 4) & 0xf];
		line[10 + (i % 16) * 3 + 1] = hex[pc[i] & 0xf];

		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			line[59 + (i % 16)] = '.';
		} else {
			line[59 + (i % 16)] = pc[i];
		}
	}

	while ((i % 16) != 0) {
		line[10 + (i % 16) * 3 + 0] = ' ';
		line[10 + (i % 16) * 3 + 1] = ' ';
		line[59 + (i % 16)] = ' ';
		i++;
	}

	printf("%.*s\n", 128, line);
	lines++;
	return lines;
}

void add_route(int family, char *subnet, char *ifname)
{
	struct nl_sock *sock = nl_socket_alloc();
	nl_connect(sock, NETLINK_ROUTE);

	struct nl_cache *link_cache;
	struct rtnl_link *link;

	// Get link index for tap0
	rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
	link = rtnl_link_get_by_name(link_cache, ifname);
	int ifindex = rtnl_link_get_ifindex(link);

	// Build route
	struct rtnl_route *route = rtnl_route_alloc();
	struct nl_addr *dst;
	nl_addr_parse(subnet, family, &dst);
	rtnl_route_set_dst(route, dst);
	rtnl_route_set_table(route, RT_TABLE_MAIN);

	struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);
	rtnl_route_add_nexthop(route, nh);

	// Add route
	rtnl_route_add(sock, route, 0);

	// Cleanup
	rtnl_route_put(route);
	nl_addr_put(dst);
	rtnl_link_put(link);
	nl_cache_free(link_cache);
	nl_socket_free(sock);
}

/* to get good perf on TX we want VIRTIO_F_NOTIFY_ON_EMPTY. Otherwise,
 * we'll get plenty of notifications, even when using
 * VIRTQ_AVAIL_F_NO_INTERRUPT.  With NOTIFY_ON_EMPTY we only get event
 * when the flush is complete, which is rarer. */

#define PACKETS 512
int main()
{
	char tap_name[16];
	int tap_fd = tap_open("tap0", tap_name, sizeof(tap_name), IFF_NAPI );
	printf("[ ] Tap tunnel name: %s\n", tap_name);
	tap_bring_up(tap_fd);

	tap_set_offloads(tap_fd);

	int vhost_fd = vhost_open();

	char *buf_rx = calloc(1, PACKETS * 2048);
	char *buf_tx = calloc(1, PACKETS * 2048);
	struct iovec iov[] = {{.iov_base = buf_rx, .iov_len = 2048*PACKETS},
			      {.iov_base = buf_tx, .iov_len = 2048 * PACKETS}};

	uint8_t mac[6] = {0xce, 0xdd, 0xba, 0x1f, 0x50, 0x82};
	// tap_get_src_mac(tap_fd, mac);
	printf("MAC address of tap0: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1],
	       mac[2], mac[3], mac[4], mac[5]);

	add_route(AF_INET, "10.10.10.0/24", "tap0");
	vhost_set_mem_table(vhost_fd, iov, 2);

	struct vring_split *vrings[2];
	vrings[0] = vring_split_new(PACKETS*4, 0);
	vrings[1] = vring_split_new(PACKETS*4, 1);


	vhost_setup_vring_split(vhost_fd, 0, vrings[0], tap_fd);
	vhost_setup_vring_split(vhost_fd, 1, vrings[1], tap_fd);

	// RX
	{
		vring_recycle_bump(vrings[0], 0); // must be zero here
		int id;
		int i;
		int pkts_rx = PACKETS/2 -1;
		for (i=0; i<pkts_rx; i++) {
			vring_desc_put(vrings[0],
				       &(struct iovec){.iov_base = buf_rx + 2048*i, .iov_len = 2048}, 1,
				       &id);
			//vring_print_id(vrings[0], id);
		}
		vring_kick(vrings[0], pkts_rx);
	}


	// TX
	uint8_t payload[] =
		"\xff\xff\xff\xff\xff\xff" // Destination MAC
		"\x00\x00\x22\x33\x44\x55" // Source MAC
		"\x08\x00"		   // EtherType: IPv4
		"\x45\x00\x00\xc0\xa0\xa7\x40\x00\x40\x11\xd9\x5f\x0a\x0a\x0a\x0a"
		"\xac\x11\x00\x01\xac\x60\x11\x51\x00\xac\xca\xb2\x5a\x01\x00\xa1"
		"\xf7\x4c\x9c\x5e\xc0\x19\x31\x6d\xf7\x4c\x9c\xff\xc2\x65\x07\x34"
		"\x8b\xd0\x6f\x8f\x02\xb3\x98\x4e\x05\x32\xc7\xbe\xf6\xbc\xf9\xeb"
		"\xc4\x7e\x35\xd4\x77\x49\xb5\xf6\xce\xb0\x77\x36\x3a\xc0\xfa\x98"
		"\x16\x48\x18\x1f\x7d\x96\xa8\x7a\xc9\x26\xa8\x02\x92\xb0\xdb\xdc"
		"\x4d\x7d\x0b\xb1\x87\xea\x26\x1f\x10\xa1\x51\xfc\xfe\x2d\xf8\xff"
		"\x67\x95\xaf\xff\x55\xc9\xa9\xfe\xac\xf3\x09\x49\x01\x31\x6d\xf7"
		"\x4c\x9c\x5e\xc0\x19\x31\x6d\xf7\x4c\x9c\xff\xc2\x65\x07\x34\x8b"
		"\xea\x67\xcf\x82\x66\xfc\xcd\x27\x83\x5b\x3b\x76\x59\xc2\x1e\x35"
		"\x6a\x8b\x83\x37\xda\xf8\xa4\xe2\xa6\x92\xff\xb2\x3e\xfa\xb3\x45"
		"\x43\xdb\x8a\xf4\x02\xce\x59\x76\xf2\x0c\x30\xb4\x7e\x52\x6f\x25";

	struct virtio_net_hdr hdr = {
		.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
		.hdr_len = 14 + 20 + 8,
		.num_buffers = 0,
		.csum_offset = 6,
		.csum_start = 14 + 20,
	};

	int tx_size = 12 + sizeof(payload) + 1024;

	uint64_t t0;
	if (1) {
		int pkts_tx = PACKETS;
		vring_recycle_bump(vrings[1],pkts_tx/2);
		int off;
		for (off = 0; off < 1024 * pkts_tx; off += 1024) {
			memcpy(buf_tx + off, &hdr, sizeof(hdr));
			memcpy(buf_tx + off + 12, payload, sizeof(payload));
			memcpy(buf_tx + off + 12 + 6, mac, 6);
			memcpy(buf_tx + off + 12 + 0, mac, 6);
			int id;
			vring_desc_put(
				vrings[1],
				&(struct iovec){.iov_base = buf_tx + off, .iov_len = tx_size}, 1,
				&id);
			// vring_print_id(vrings[1], id);
		}
		t0 = realtime_now();
		vring_kick(vrings[1],pkts_tx);
	}
	// Always suppressed for TX
	//vring_set_suppress_notifications(vrings[1]);


	int call[2];
	int errfd[2];
	call[0] = vring_callfd(vrings[0]);
	call[1] = vring_callfd(vrings[1]);
	errfd[0] = vring_errfd(vrings[0]);
	errfd[1] = vring_errfd(vrings[1]);

	int epfd = epoll_create1(0);
	if (epfd == -1) {
		error(-1, errno, "epoll_create1");
	}

	int fds[] = { call[0], call[1], errfd[0], errfd[1] };
	for (int i = 0; i < 4; ++i) {
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = fds[i],
		};
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ev) == -1) {
			error(-1, errno, "epoll_ctl");
		}
	}


	uint64_t rx_counter = 0;
	uint64_t rx_wakeup = 0;
	uint64_t tx_counter = 0;
	uint64_t tx_wakeup = 0;
	//uint64_t xt0 = realtime_now();
	while (1) {
		// vring_print_id(vrings[0],0);
		// vring_print_id(vrings[1],0);
		if (realtime_now() - t0 > 1000000000ULL) {
			double td = (realtime_now() - t0) / 1000000000ULL;
			t0 = realtime_now();
			if (1 || tx_counter == 0) {
				printf("*rx* ");
				vring_kick(vrings[0], -1);
				printf("*tx* ");
				vring_kick(vrings[1], -1);
				printf("| ");
			}


			printf("rx=%.3f kpps / %.1fppw", rx_counter / 1000. / td, rx_counter * 1.0/rx_wakeup);
			printf("  tx=%.3f kpps / %.1fppw\n", tx_counter / 1000. / td, tx_counter*1.0 / tx_wakeup);
			rx_counter = 0;
			rx_wakeup = 0;
			tx_counter = 0;
			tx_wakeup = 0;
		}
		// unsigned int len = -1;
		//int r;

		struct epoll_event events[4];
		int nfds = epoll_wait(epfd, events, 4, 1000);
		if (nfds == -1) {
			if (errno == EAGAIN || errno == EINTR) continue;
			error(-1, errno, "epoll_wait");
		}

		/* fd_set rfds; */
		/* FD_ZERO(&rfds); */
		/* FD_SET(call[0], &rfds); */
		/* FD_SET(call[1], &rfds); */
		/* FD_SET(errfd[0], &rfds); */
		/* FD_SET(errfd[1], &rfds); */

		/* select(errfd[1] + 1, &rfds, NULL, NULL, &(struct timeval){.tv_sec = 1}); */
		// nanosleep(&(struct timespec){.tv_nsec=100}, NULL);
		struct virtq_used_elem pkts[PACKETS];
		uint64_t val;
		for (int ii = 0; ii < nfds; ++ii) {
		if (events[ii].data.fd == call[0]) {
			rx_wakeup++;
			//vring_set_suppress_notifications(vrings[0]);
			read(call[0], &val, sizeof(val));

			int idx = vring_get_buf_bulk(vrings[0], pkts, PACKETS);
			rx_counter += idx;

			//vring_recycle_bump(vrings[0], idx);
			int needs_kick = vring_recycle_bulk(vrings[0], pkts, idx);
			if (1|| needs_kick) {
//				printf("kick rx\n");
				vring_kick(vrings[0], 0);
			}
		}

		if (events[ii].data.fd == call[1]) {
			tx_wakeup ++;
			read(call[1], &val, sizeof(val));

			while (1) {
			int needs_kick = 0;
				int idx = vring_get_buf_bulk(vrings[1], pkts, PACKETS);
				if (idx == 0)
					break;
				tx_counter += idx;

				// printf("tx rx num=%d\n", idx);
				//vring_recycle_bump(vrings[1], idx);
				needs_kick = vring_recycle_bulk(vrings[1], pkts, idx);
			
//				nanosleep(&(struct timespec){.tv_nsec=100000}, NULL);

			if (needs_kick){
				//printf("td=%.3fms\n", (realtime_now() - xt0)/1000000.);
				vring_kick(vrings[1], 0);
				//printf("tx kick\n");
			}
			}
		}
		if (events[ii].data.fd == errfd[0]) {
			read(errfd[0], &val, sizeof(val));
			error(-1, ECOMM, "Mem error reported on RX queue");
		}
		if (events[ii].data.fd == errfd[1]) {
			read(errfd[1], &val, sizeof(val));
			error(-1, ECOMM, "Mem error reported on TX queue");
		}
		}
	}

	return 0;
}
