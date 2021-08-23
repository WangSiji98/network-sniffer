/*
=====================================================================
    Filename:sniffer.h
    Author：Siji
    Description:  网络数据嗅探类的类声明头文件
=====================================================================
*/

#ifndef SNIFFER_H_
#define SNIFFER_H_

#include<pcap.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include<time.h>
#include<stdio.h>
#include<errno.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include<vector>
#include"headerType.h"

#define MAXBYTES2CAPTURE 2048
#define PCAP_OPENFLAG_PROMISCUOUS_1 1
#define PCAP_SRC_FILE_1 2
#define PCAP_OPENFLAG_NOCAPTURE_LOCAL_1	8
#define IPTOSBUFFERS_1 12

class Sniffer
{
 public:
   Sniffer();
   ~Sniffer();

   typedef void (*C_B_fun)(u_char *,const struct pcap_pkthdr *, const u_char *);//定义callback函数指针

   bool findAllNetDevs();

   void freeNetDevsMem();											// 释放网络设备信息占据的堆内存

   bool openNetDev(char *devStr, 								// 根据名称打开网络设备
                        int flag = PCAP_OPENFLAG_PROMISCUOUS_1,
                        int Len_Packet = 65536);

  bool openNetDev(int DevNum, 									// 根据序号打开网络设备
         				  int flag = PCAP_OPENFLAG_PROMISCUOUS_1,
         					int LengthLimit = 65536);

  bool setDevsFilter(const char *szFilter);						// 对当前打开设备设置过滤器


  bool captureByCallBack(C_B_fun func,u_char* user);						// 以回调函数方式捕获数据

  bool closeNetDev();												// 关闭当前打开的网络设备


  bool openDumpFile(const char *FileName);						// 打开堆文件（文件保存数据包）

  void saveCaptureData(u_char *dumpFile, 							// 保存捕获的数据到文件
            struct pcap_pkthdr *pkthdr,
            u_char *packet);

  void saveCaptureData();											// 保存捕获的数据到文件

  void closeDumpFile();											// 关闭堆文件

public:
  struct	pcap_pkthdr *pkthdr;
  const u_char *packet;
  char *devStr;

  bool getNetDevInfo();
  int	 captureOnce();												// 捕获一次网络数据包
  void consolePrint();											// 控制台打印网络设备信息

  bool OpenSaveCaptureFile(const char *szFileName);

  std::vector<NetDevInfo> netDevsInfo;
  std::vector<SnifferData> sniffersData;
  std::vector<QQ> QQnum;
  void showSnifferData();
  void showSnifferData(SnifferData tmp);
  void showQQnum();
protected:
	char *iptos(u_long in);
	char *ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

  pcap_if_t		*pAllNetDevs;					// 网络设备列表信息链表指针
	int				NetDevsNum;					// 网络设备数量
	pcap_t			*deScr;						// 当前打开的设备句柄（指针）
  bpf_u_int32 netaddr = 0; //存放ip地址
  bpf_u_int32 netmask = 0; //存放子网掩码
  pcap_dumper_t *dumpFile;  // 要保存到的文件指针

	char errbuf[MAXBYTES2CAPTURE];					// 错误信息缓冲

};

 #endif //SNIFFER_H_
