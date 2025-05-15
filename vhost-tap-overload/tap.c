#include <string.h>
#include <error.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>

#include "common.h"

#define MIN(x,y) ({ \
    typeof(x) _x = (x);     \
    typeof(y) _y = (y);     \
    (void) (&_x == &_y);    \
    _x <= _y ? _x : _y; })

int tap_open(const char *usr_tap_name, char *new_tap_name, size_t new_tap_name_sz, uint32_t ifr_extra_flags){
	int auto_delete = 1;
	const char *tap_name = "\x00";

	if (usr_tap_name && strlen(usr_tap_name)>0) {
		tap_name = usr_tap_name;
		auto_delete = 0;
	}

	/* First, whatever you do, the device /dev/net/tun must be
	 * opened read/write. That device is also called the clone
	 * device, because it's used as a starting point for the
	 * creation of any tun/tap virtual interface. */
	char *clone_dev_name = "/dev/net/tun";
	int tap_fd  = open(clone_dev_name, O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (tap_fd < 0) {
		error(-1, errno, "open(%s)", clone_dev_name);
	}

	/* CAP_NET_ADMIN */
	struct ifreq ifr = {};
	memcpy(ifr.ifr_name, tap_name, MIN(IFNAMSIZ, (int)strlen(tap_name)));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR | ifr_extra_flags;
	int r = ioctl(tap_fd, TUNSETIFF, &ifr);
	if (r != 0) {
		error(-1, errno, "ioctl(TUNSETIFF)");
	}

	memset(&ifr, 0, sizeof(ifr));
	r = ioctl(tap_fd, TUNGETIFF, &ifr);
	if (r != 0) {
		error(-1, errno, "ioctl(TUNGETIFF)");
	}

	if (new_tap_name) {
		snprintf(new_tap_name, new_tap_name_sz,"%.*s", IFNAMSIZ, ifr.ifr_name);
	}

	if (auto_delete == 1) {
		ioctl(tap_fd, TUNSETPERSIST, 0);
	}

	/* I've had bad luck setting this to value other than the one
	 * supported by the kernel (typically 12 bytes). */

	int len = 0;
	r = ioctl(tap_fd, TUNGETVNETHDRSZ, &len);
	if (r != 0) {
		error(-1, errno, "ioctl(TUNSETVNETHDRSZ)");
	}

	printf("len=%d\n", len);
	len=12;
	r = ioctl(tap_fd, TUNSETVNETHDRSZ, &(int){len});
	if (r != 0) {
		error(-1, errno, "ioctl(TUNSETVNETHDRSZ)");
	}

	return tap_fd;
}

#ifndef TUN_F_USO4
#  define TUN_F_USO4 0x20
#endif
#ifndef TUN_F_USO6
#  define TUN_F_USO6 0x40
#endif

int tap_set_offloads(int tap_fd)
{

	unsigned off_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
	int r = ioctl(tap_fd, TUNSETOFFLOAD, off_flags);
	if (r != 0) {
		error(-1, errno, "ioctl(TUNSETOFFLOAD) - failed to set standard offloads CSUM TSO4 and TSO6");
	}

	/* Must set USO4 and USO6 at the same time. */
	off_flags |=  TUN_F_USO4 | TUN_F_USO6;
	r = ioctl(tap_fd, TUNSETOFFLOAD, off_flags);
	if (r != 0) {
		error(-1, errno, "ioctl(TUNSETOFFLOAD) - failed to set new offloads USO4 and USO6. Are you running kernel 6.2+?");
	}
	return 0;
}

int tap_attach_queue(int tap_fd)
{
	int r = ioctl(tap_fd, TUNSETQUEUE, &(struct ifreq){
			.ifr_flags = IFF_ATTACH_QUEUE
		});
	if (r != 0) {
		error(-1, errno, "TUNSETQUEUE/IFF_ATTACH_QUEUE");
	}
	return 0;
}

int tap_detach_queue(int tap_fd)
{
	int r = ioctl(tap_fd, TUNSETQUEUE, &(struct ifreq){
			.ifr_flags = IFF_DETACH_QUEUE
		});
	if (r != 0) {
		error(-1, errno, "TUNSETQUEUE/IFF_DETACH_QUEUE");
	}
	return 0;
}

int tap_bring_up(int tap_fd) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	if (ioctl(tap_fd, TUNGETIFF, &ifr) < 0) {
		error(-1, errno, "TUNGETIFF");
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		error(-1, errno, "socket");
	}

	if (0) {
		/* memset(&ifr, 0, sizeof(ifr)); */
		/* strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1); */
		ifr.ifr_qlen = 1024;

		if (ioctl(sock, SIOCSIFTXQLEN, &ifr) < 0) {
			error(errno, -1, "ioctl SIOCSIFTXQLEN");
		}
	}
	
	// Get current flags
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		error(-1, errno, "SIOCGIFFLAGS");
	}

	// Set interface up
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		error(-1, errno, "SIOCSIFFLAGS");
	}

	int i;
	for (i=0; i<40; i++) {
		sched_yield();
		nanosleep(&(struct timespec){.tv_nsec=1000ULL}, NULL);
	}

	if (1) {
		system("tc qdisc add dev tap0 ingress");
		system("tc filter add dev tap0 ingress protocol ip u32 match ip dst 172.17.0.1/32      action  mirred egress redirect dev tap0");
		// system("tc qdisc add dev tap0 root netem delay 1ms 1ms");
	}
	close(sock);
	return 0;
}

int tap_get_src_mac(int tap_fd, uint8_t src_mac[6]) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	if (ioctl(tap_fd, TUNGETIFF, &ifr) < 0) {
		error(-1, errno, "TUNGETIFF");
	}

	char ifname[IFNAMSIZ];
	strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
	printf("ifrname %s\n", ifname);

	// Prepare ifr again with just the interface name
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		error(-1, errno, "socket");
	}

	// Get current flags
        int r = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (r<0) {
		error(-1, errno, "SIOCGIFHWADDR");
	}

	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
	printf("mac %02x %02x\n", src_mac[0], src_mac[1]);
	close(sock);
	return 0;
}
