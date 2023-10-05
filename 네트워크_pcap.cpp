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
}ethernet;//14����Ʈ �̴��� ����ü 

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
}ipv4;//20����Ʈ ������ ����ü 

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
}tcp;//20����Ʈ tcp ����ü 

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}//���� ����Լ� 

typedef struct {
    char* dev_;
} Param; //�̸��� ������ ����ü �ʵ� 

Param param = {
    .dev_ = NULL
};//����ü �ʵ� �ʱ�ȭ 

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}//���� �Ҹ����� ���� ��°� �Բ� false ��ȯ 
//���� ������ ��Ʈ��ũ �������̽� �̸� ����� true ��ȯ 

int main(int argc, char* argv[]) {
	int port = 0,Off = 0;//���� ������ ���� 
    if (!parse(&param, argc, argv))
        return -1;//�Ľ� �Լ� ȣ�� ���н� ���α׷� ���� 

    char errbuf[PCAP_ERRBUF_SIZE];//���� �޽��� ���� �迭 
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;//���� �޽��� ��°� �Բ� ���α׷� ���� 
    }

    while (true) {
        struct pcap_pkthdr* header;//��Ŷ ��� ����ü ������ 

        const u_char* packet;//��Ŷ �����Ϳ� ���� 
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;//��Ŷ �� ��ٸ��� 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;//���� �޽��� ��°� �Բ� ���� ���� 
        }

        ethernet* eth = (ethernet *)packet;//�̴��ݿ� ��Ŷ �� 14����Ʈ��ŭ ���� 
		ipv4* v4 = (ipv4 *) (packet+sizeof(ethernet));//�̴��ݿ� ������ �κ� �����ϰ� 20����Ʈ��ŭ ����  
		tcp* t = (tcp *) (packet+sizeof(ethernet)+sizeof(ipv4));// �̴��ݰ� IP�� ������ �κ� �����ϰ� 20����Ʈ��ŭ ���� 
		
		if(!(eth->type[0]==0x08&&eth->type[1]==0x00)){
			continue;//IPV4�� �ƴ϶�� �ٽ� �ҷ����� 
		}
		if(v4->Protocol!=0x06){
			continue;//TCP�� �ƴ϶�� �ٽ� �ҷ����� 
		}
		
        printf("Src Mac : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            if (i != MAC_ADDR_LEN - 1) {
                printf("%02X:", eth->src_mac[i]);
            } else {
                printf("%02X\n", eth->src_mac[i]);
            }
        }//Src Mac �� ��°� �ٳѱ� 
        
        printf("Dst Mac : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            if (i != MAC_ADDR_LEN - 1) {
                printf("%02X:", eth->dst_mac[i]);
            } else {
                printf("%02X\n", eth->dst_mac[i]);
            }
        }//Dst Mac �� ��°� �ٳѱ� 
        
        printf("Src IP : ");
        for (int i = 0; i < IP_ADDR_LEN; i++) {
            if (i != IP_ADDR_LEN - 1) {
                printf("%d.", v4->src_ip[i]);
            } else {
                printf("%d\n", v4->src_ip[i]);
            }
        }//Src IP ��°� �ٳѱ� 
        
        printf("Dst IP : ");
        for (int i = 0; i < IP_ADDR_LEN; i++) {
            if (i != IP_ADDR_LEN - 1) {
                printf("%d.", v4->dst_ip[i]);
            } else {
                printf("%d\n", v4->dst_ip[i]);
            }
        }//Dst IP ��°� �ٳѱ� 
        
		port = t->Source_Port[0] << 8;//����Ʈ �������� 0x0000�÷� ������� 
		port += t->Source_Port[1];
		printf("Src port : %d\n",port);//��Ʈ �� ��� 
		port=0;//��Ʈ �� �ʱ�ȭ 
        
        port = t->Destination_Port[0] << 8;
		port += t->Destination_Port[1];//����Ʈ �������� 0x0000�÷� ������� 
		printf("Dst port : %d\n",port);//��Ʈ �� ��� 
		port=0;//��Ʈ �� �ʱ�ȭ 
		
		printf("Total Bytes : %u\n", header->caplen);//�� ����Ʈ �� ��� 
		
		if((t->Offset[0]&0xF0)!=0x50){//Offset�� ���� 0x50�� �ƴ϶�� 
			Off = t->Offset[0] >> 4; //����Ʈ �����ڷ� �����ϱ� ���� �ٲ� 
			Off = Off*4;//Off�� * 4����Ʈ = tcp ũ��  
			printf("Payload(Data) : ");
        	for(int i=34+Off; i<50+Off && i<header->caplen; i++) {
            printf("%02X ",packet[i]);//�� ����Ʈ ���� �����ϰų� 16���� �� ����ϸ� ���� 
			}
			printf("\n");
			Off=0;
		}else{//�ƹ� �̻� ���ٸ� 
			printf("Payload(Data) : ");
        	for(int i=54; i<70 && i<header->caplen; i++) {
            printf("%02X ",packet[i]);//�� ����Ʈ ���� �����ϰų� 16���� �� ����ϸ� ���� 
			}
			printf("\n");
    	}
	}
    pcap_close(pcap);//pcap �ڵ� �ݱ� 
    return 0;
}

