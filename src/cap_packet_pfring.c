#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>

#include <pcap.h>
#include <pfring.h>
#include <time.h>

#define DEFAULT_SNAPLEN 1500

typedef struct {
	char *p_ch_dev_name;
	bpf_u_int32 *p_uint32_net_addr;
	bpf_u_int32 *p_uint32_netmask;
} if_info;
if_info *p_if_info_1 = NULL;
char *p_ch_err_buf = NULL;

extern void args_parse(int, char **);
extern void init(if_info *);
extern void list_if(if_info *);
extern void get_if_info(if_info *);
extern void open_if_and_cap_loop(void);
extern void quit(void);

extern void callback_process_packet(const struct pfring_pkthdr *, const u_char *, const u_char *);

extern void sigalrm_response(int);
extern void sigterm_response(int);

int int_cap_time_s = 0;
char *p_ch_if_name = NULL;
char *p_ch_filter_rule = NULL;

pfring *p_pfring_0 = NULL;

unsigned int packet_count = 0;
unsigned long cap_byte_count = 0;

int main(int argc, char *argv[])
{
	args_parse(argc, argv);

	signal(SIGALRM, sigalrm_response); // 注册信号函数
	signal(SIGTERM, sigterm_response);

	// libpcap get if info
	if_info *p_if_info_0 = NULL;
	p_if_info_0 = (if_info *)malloc(sizeof(if_info));
	p_if_info_1 = p_if_info_0;
	init(p_if_info_0);
	list_if(p_if_info_0);
	get_if_info(p_if_info_0);

	if (int_cap_time_s != 0)
		alarm(int_cap_time_s);

	open_if_and_cap_loop();

	if (pfring_set_bpf_filter(p_pfring_0, p_ch_filter_rule) != 0) { // 设置过滤器。
		fprintf(stderr, "\n\terr: %s\n", "failed to applicate the BPF filter rule!");
                exit(1);
	}

	p_if_info_0 = NULL;
	quit();
	
	fprintf(stdout, "number of packets and bytes captured: %u, %lu\n", packet_count, cap_byte_count);

	return 0;
}

void sigterm_response(int sig)
{
	if (SIGTERM == sig) {
		quit();
		fprintf(stdout, "number of packets and bytes captured: %u, %lu\n", packet_count, cap_byte_count);
		exit(0);
	}
}

void sigalrm_response(int sig)
{
	if (SIGALRM == sig) {
		quit();
		fprintf(stdout, "number of packets and bytes captured: %u, %lu\n", packet_count, cap_byte_count);
		exit(0);
	}
}





// char *p_ch_if_name = NULL;
// char *p_ch_filter_rule = NULL;
void args_parse(int argc, char *argv[])
{
	int_cap_time_s = atoi(argv[1]);
	p_ch_filter_rule = argv[2];
	p_ch_if_name = argv[3];
}

void init(if_info *p_if_info_0)
{
	p_if_info_0->p_ch_dev_name = NULL;
	p_if_info_0->p_uint32_net_addr = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
	p_if_info_0->p_uint32_netmask = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));

	p_pfring_0 = (pfring *)malloc(sizeof(pfring));

	p_ch_err_buf = (char *)malloc(sizeof(char) * PCAP_ERRBUF_SIZE);
}

void list_if(if_info *p_if_info_0)
{
	p_if_info_0->p_ch_dev_name = pcap_lookupdev(p_ch_err_buf);

	if (p_if_info_0->p_ch_dev_name == NULL)
	{
		fprintf(stderr, "\n\terr: %s\n", p_ch_err_buf);
		exit(1);
	}
	else
		fprintf(stdout, "if info: \n\tif list: \n\t%s\n", p_if_info_0->p_ch_dev_name);

}

void get_if_info(if_info *p_if_info_0)
{
	if (0 != pcap_lookupnet(p_if_info_0->p_ch_dev_name, 
				p_if_info_0->p_uint32_net_addr, 
				p_if_info_0->p_uint32_netmask, 
				p_ch_err_buf)) {
		fprintf(stderr, "\n\terr: \n\t%s/n", p_ch_err_buf);
		exit(1);
	}
	else {
		fprintf(stdout, "\n\tnet_addr is: \n\t%u.%u.%u.%u\n", 
				(*p_if_info_0->p_uint32_net_addr & 0x000000ff), 
				(*p_if_info_0->p_uint32_net_addr & 0x0000ff00) >> 8, 
				(*p_if_info_0->p_uint32_net_addr & 0x00ff0000) >> 16, 
				(*p_if_info_0->p_uint32_net_addr & 0xff000000) >> 24); // 网络传输为大端传输，所以低字节存放在高地址。
		fprintf(stdout, "\n\tnetmask is: \n\t%u.%u.%u.%u\n\n\n\n", 
				(*p_if_info_0->p_uint32_netmask & 0x000000ff), 
				(*p_if_info_0->p_uint32_netmask & 0x0000ff00) >> 8, 
				(*p_if_info_0->p_uint32_netmask & 0x00ff0000) >> 16, 
				(*p_if_info_0->p_uint32_netmask & 0xff000000) >> 24);
		fprintf(stdout, "\n\n");
	}
}

void open_if_and_cap_loop(void)
{
	pfring *p_pfring_0 = pfring_open(p_ch_if_name, DEFAULT_SNAPLEN, PF_RING_PROMISC);
	if (NULL == p_pfring_0) {
		printf("open device failed!\n");
		exit(1);
	}

	// enum packet_direction { rx_and_tx_direction = 0, rx_only_direction, tx_only_direction };
	if (0 != pfring_set_direction(p_pfring_0, rx_only_direction)) {
		printf("set direction failed!\n");
		exit(1);
	}

	// enum socket_mode { send_and_recv_mode = 0, send_only_mode, recv_only_mode };
	if (0 != pfring_set_socket_mode(p_pfring_0, recv_only_mode)) {
		printf("set socket mode failed!\n");
		exit(1);
	}

	if (0 != pfring_enable_ring(p_pfring_0)) {
		printf("enable ring failed!\n");
		pfring_close(p_pfring_0);
		exit(1);
	}

	pfring_loop(p_pfring_0, callback_process_packet, (u_char *)NULL, 0);
}

void callback_process_packet(const struct pfring_pkthdr *p_pfring_pkthdr_h, 
				const u_char *p_uch_0, 
				const u_char *p_uch_user_data)
{
	packet_count++;

	printf("包基本信息：");
	printf("\npacket_id is: %u\n", packet_count);
	printf("length of portion present: %d\n", p_pfring_pkthdr_h->caplen); // 取长
	printf("length this packet: %d\n", p_pfring_pkthdr_h->len); // 实际长
	printf("recieved time: %s", ctime((const time_t *)&p_pfring_pkthdr_h->ts.tv_sec)); // 时间戳

	printf("\n以太网首部信息提取：\n");
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", p_uch_0[0], p_uch_0[1], p_uch_0[2], p_uch_0[3], p_uch_0[4], p_uch_0[5]);
	printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", p_uch_0[6], p_uch_0[7], p_uch_0[8], p_uch_0[9], p_uch_0[10], p_uch_0[11]);

	printf("type: %02x%02x\n", p_uch_0[12], p_uch_0[13]);

	printf("\nIP 首部信息提取：\n");
	printf("src ip: %u.%u.%u.%u\n", p_uch_0[26], p_uch_0[27], p_uch_0[28], p_uch_0[29]);
	printf("dst ip: %u.%u.%u.%u\n", p_uch_0[30], p_uch_0[31], p_uch_0[32], p_uch_0[33]);
	printf("version: %u\n", (p_uch_0[14] & 0xf0) >> 4);
	printf("header length: %u byte\n", (p_uch_0[14] & 0x0f) * 4);
	printf("total length: %u byte\n", p_uch_0[16] * 0xff + p_uch_0[17]);
	printf("TTL: %u\n", p_uch_0[22]);
	printf("protocol: %u ", p_uch_0[23]);
	if (1 == p_uch_0[23])
		 printf("(ICMP)\n");
	else if (6 == p_uch_0[23])
		printf("(TCP)\n");
	else if (17 == p_uch_0[23])
		printf("(UDP)\n");

	if (6 == p_uch_0[23]) {
		printf("\nTCP 首部信息提取：\n");
		printf("src port: %u\n", p_uch_0[34 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[35 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
		printf("dst port: %u\n", p_uch_0[36 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[37 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
	} else if (17 == p_uch_0[23]) {
		printf("\nUDP 首部信息提取：\n");
		printf("src port: %u\n", p_uch_0[34 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[35 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
		printf("dst port: %u\n", p_uch_0[36 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[37 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
	} else if (1 == p_uch_0[23])
		printf("\nICMP 无端口号\n");
	// printf("src port: %u\n", p_uch_0[34 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[35 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
	// printf("dst port: %u\n", p_uch_0[36 + ((p_uch_0[14] & 0x0f) * 4) - 20] * 0xff + p_uch_0[37 + ((p_uch_0[14] & 0x0f) * 4) - 20]);
	// printf("src port: %u\n", p_uch_0[34] * 0xff + p_uch_0[35]);
	// printf("dst port: %u\n", p_uch_0[36] * 0xff + p_uch_0[37]);

	printf("\n数据包内容：\n");

	for (int i = 0; i < p_pfring_pkthdr_h->len; ++i) {
		cap_byte_count++;
		printf(" %02x", p_uch_0[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	putchar('\n');
	putchar('\n');
	putchar('\n');
	putchar('\n');
}

void close_if(void)
{
	pfring_breakloop(p_pfring_0);
	pfring_close(p_pfring_0);
	fprintf(stdout, "\nif has closed!\n\n");
}

void quit(void)
{
	close_if();

	// free(p_if_info_1->p_ch_dev_name);
	p_if_info_1->p_ch_dev_name = NULL;

	free(p_if_info_1->p_uint32_net_addr);
	p_if_info_1->p_uint32_net_addr = NULL;

	free(p_if_info_1->p_uint32_netmask);
	p_if_info_1->p_uint32_netmask = NULL;

	p_if_info_1 = NULL;

	free(p_ch_err_buf);
	p_ch_err_buf= NULL;
}
