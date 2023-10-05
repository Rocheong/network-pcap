#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

typedef struct _ethernet
{
    unsigned char dst_mac[MAC_ADDR_LEN];
    unsigned char src_mac[MAC_ADDR_LEN];
    unsigned char type[2];
}ethernet;//14바이트 이더넷 구조체 

typedef struct _ipv4
{
    unsigned char version;
    unsigned char TOS;
    unsigned short Total_Length;
    unsigned short Identificaion;
    unsigned short IP_Flags_Fragment_Offset;
    unsigned char TTL;
    unsigned char Protocol;
    unsigned short Header_checksum;
    unsigned char src_ip[IP_ADDR_LEN];
    unsigned char dst_ip[IP_ADDR_LEN];
}ipv4;//20바이트 아이피 구조체 

typedef struct _tcp
{
    unsigned char Source_Port[2];
    unsigned char Destination_Port[2];
    unsigned char Sequence_Number[4];
    unsigned char Acknowledge_Number[4];
    unsigned char Offset[2];
    unsigned short Window;
    unsigned short check_sum;
    unsigned short urgent_pointer;
}tcp;//20바이트 tcp 구조체 

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}//사용법 출력함수 

typedef struct {
    char* dev_;
} Param; //이름을 저장할 구조체 필드 

Param param = {
    .dev_ = NULL
};//구조체 필드 초기화 

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}//조건 불만족시 사용법 출력과 함께 false 반환 
//조건 만족시 네트워크 인터페이스 이름 저장과 true 반환 

int main(int argc, char* argv[]) {
	int port = 0,Off = 0;//값을 저장할 변수 
    if (!parse(&param, argc, argv))
        return -1;//파싱 함수 호출 실패시 프로그램 종료 

    char errbuf[PCAP_ERRBUF_SIZE];//오류 메시지 저장 배열 
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;//오류 메시지 출력과 함께 프로그램 종료 
    }

    while (true) {
        struct pcap_pkthdr* header;//패킷 헤더 구조체 포인터 

        const u_char* packet;//패킷 포인터에 저장 
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;//패킷 값 기다리기 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;//오류 메시지 출력과 함께 루프 종료 
        }

        ethernet* eth = (ethernet *)packet;//이더넷에 패킷 값 14바이트만큼 저장 
		ipv4* v4 = (ipv4 *) (packet+sizeof(ethernet));//이더넷에 저장한 부분 제외하고 20바이트만큼 저장  
		tcp* t = (tcp *) (packet+sizeof(ethernet)+sizeof(ipv4));// 이더넷과 IP에 저장한 부분 제외하고 20바이트만큼 저장 
		
		if(!(eth->type[0]==0x08&&eth->type[1]==0x00)){
			continue;//IPV4가 아니라면 다시 불러오기 
		}
		if(v4->Protocol!=0x06){
			continue;//TCP가 아니라면 다시 불러오기 
		}
		
        printf("Src Mac : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            if (i != MAC_ADDR_LEN - 1) {
                printf("%02X:", eth->src_mac[i]);
            } else {
                printf("%02X\n", eth->src_mac[i]);
            }
        }//Src Mac 값 출력과 줄넘김 
        
        printf("Dst Mac : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            if (i != MAC_ADDR_LEN - 1) {
                printf("%02X:", eth->dst_mac[i]);
            } else {
                printf("%02X\n", eth->dst_mac[i]);
            }
        }//Dst Mac 값 출력과 줄넘김 
        
        printf("Src IP : ");
        for (int i = 0; i < IP_ADDR_LEN; i++) {
            if (i != IP_ADDR_LEN - 1) {
                printf("%d.", v4->src_ip[i]);
            } else {
                printf("%d\n", v4->src_ip[i]);
            }
        }//Src IP 출력과 줄넘김 
        
        printf("Dst IP : ");
        for (int i = 0; i < IP_ADDR_LEN; i++) {
            if (i != IP_ADDR_LEN - 1) {
                printf("%d.", v4->dst_ip[i]);
            } else {
                printf("%d\n", v4->dst_ip[i]);
            }
        }//Dst IP 출력과 줄넘김 
        
		port = t->Source_Port[0] << 8;//시프트 연산으로 0x0000꼴로 만들어줌 
		port += t->Source_Port[1];
		printf("Src port : %d\n",port);//포트 값 출력 
		port=0;//포트 값 초기화 
        
        port = t->Destination_Port[0] << 8;
		port += t->Destination_Port[1];//시프트 연산으로 0x0000꼴로 만들어줌 
		printf("Dst port : %d\n",port);//포트 값 출력 
		port=0;//포트 값 초기화 
		
		printf("Total Bytes : %u\n", header->caplen);//총 바이트 수 출력 
		
		if((t->Offset[0]&0xF0)!=0x50){//Offset의 값이 0x50이 아니라면 
			Off = t->Offset[0] >> 4; //시프트 연산자로 연산하기 쉽게 바꿈 
			Off = Off*4;//Off값 * 4바이트 = tcp 크기  
			printf("Payload(Data) : ");
        	for(int i=34+Off; i<50+Off && i<header->caplen; i++) {
            printf("%02X ",packet[i]);//총 바이트 수에 도달하거나 16개를 다 출력하면 멈춤 
			}
			printf("\n");
			Off=0;
		}else{//아무 이상 없다면 
			printf("Payload(Data) : ");
        	for(int i=54; i<70 && i<header->caplen; i++) {
            printf("%02X ",packet[i]);//총 바이트 수에 도달하거나 16개를 다 출력하면 멈춤 
			}
			printf("\n");
    	}
	}
    pcap_close(pcap);//pcap 핸들 닫기 
    return 0;
}

