/* blast TAP N MODE: write N frames to a tap with IFF_VNET_HDR in a tight loop,
 * print ns per packet.  tun_get_user() runs the RX path (incl. tc ingress)
 * synchronously in the writer, so the write loop time is the per-packet cost.
 * MODE: partial = CHECKSUM_PARTIAL (guest with tx csum offload, the common case)
 *       none    = no NEEDS_CSUM (ip_summed NONE)
 *       nonip   = ethertype 0x88b5 (filter exits on protocol check)                       */
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

static unsigned short ipcsum(const unsigned char *p, int n)
{
	unsigned long s = 0;
	for (int i = 0; i < n; i += 2) s += (p[i] << 8) | p[i + 1];
	while (s >> 16) s = (s & 0xffff) + (s >> 16);
	return ~s;
}

int main(int argc, char **argv)
{
	struct ifreq ifr = {0};
	unsigned char buf[2048] = {0};
	long n = atol(argv[2]);
	const char *mode = argv[3];
	int fd = open("/dev/net/tun", O_RDWR);
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
	if (fd < 0 || ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("tun"); return 1; }
	printf("ready\n"); fflush(stdout);
	getchar();

	struct virtio_net_hdr *vh = (void *)buf;
	unsigned char *f = buf + sizeof(*vh);
	unsigned char dst[6] = {2, 0, 0, 0, 0, 1}, src[6] = {2, 0, 0, 0, 0, 2};
	int payload = 64, len;
	memcpy(f, dst, 6); memcpy(f + 6, src, 6);
	if (!strcmp(mode, "nonip")) {
		f[12] = 0x88; f[13] = 0xb5;
		len = 14 + 20 + 8 + payload;
	} else {
		f[12] = 0x08; f[13] = 0x00;
		unsigned char *ip = f + 14;
		ip[0] = 0x45; ip[2] = 0; ip[3] = 20 + 8 + payload; ip[8] = 64; ip[9] = 17;
		ip[12] = 10; ip[15] = 2; ip[16] = 10; ip[17] = 1; ip[19] = 2;
		unsigned short c = ipcsum(ip, 20); ip[10] = c >> 8; ip[11] = c;
		unsigned char *u = ip + 20;
		u[0] = 4; u[1] = 0x57; u[2] = 8; u[3] = 0xae; u[5] = 8 + payload;
		len = 14 + 20 + 8 + payload;
		if (!strcmp(mode, "partial")) {
			vh->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			vh->csum_start = 34; vh->csum_offset = 6;
		}
	}
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	for (long i = 0; i < n; i++)
		if (write(fd, buf, sizeof(*vh) + len) < 0) { perror("write"); return 1; }
	clock_gettime(CLOCK_MONOTONIC, &b);
	double ns = (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
	printf("%.1f\n", ns / n); fflush(stdout);
	getchar();
	return 0;
}
