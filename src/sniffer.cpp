/*
=====================================================================
    Filename:sniffer.h
    Author：Siji
    deScription: 网络数据嗅探类的类实现文件
=====================================================================
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netdb.h>

#include "../include/sniffer.h"
#include "../include/headerType.h"

Sniffer::Sniffer()
{
  pAllNetDevs = NULL;
  NetDevsNum = 0;
  deScr = NULL;
  dumpFile = NULL;
  memset (errbuf,0,PCAP_ERRBUF_SIZE);//初始化errbuf
}

Sniffer::~Sniffer()
{
  freeNetDevsMem();
};

bool Sniffer::findAllNetDevs()
{
  freeNetDevsMem();

  if(pcap_findalldevs(&pAllNetDevs,errbuf)==-1){
      printf("error: pcap_findalldevs()%s\n",errbuf);
      return false;
  }
  for(pcap_if_t *index = pAllNetDevs;index !=NULL;index = index->next){
    NetDevsNum++;
  }

  return true;
}

bool Sniffer::openNetDev(char *devstr,int flag, int Len_Packet)	// 根据名称打开网络设备
{
  // printf("%s\n",devstr);
  devStr = devstr;
  if(deScr != NULL){
    closeNetDev();
  }

  deScr = pcap_open_live(devstr, // 设备名
                        Len_Packet, // 数据包大小限制
                        flag, // 网卡设置打开模式
                        1000,  // 读取超时时间
                        errbuf); // 错误缓冲

  if (deScr == NULL) {
        return false;
    }
  pcap_lookupnet(devStr,&netaddr,&netmask,errbuf);
  return true;
}

bool Sniffer::openNetDev(int DevNum, 									// 根据序号打开网络设备
                int flag,
                int LengthLimit )
{
  if(DevNum<1||DevNum > NetDevsNum){
    return false;
  }

  pcap_if_t *index=pAllNetDevs;

  for(int i=1;i<DevNum;++i){
      index=index->next;
  }
  if(deScr != NULL){
    closeNetDev(); //释放当前网络设备
  }
  devStr = index->name;
  // printf("80 %s\n",devStr);
  deScr = pcap_open_live(index->name,LengthLimit,flag,1000,errbuf);
  pcap_lookupnet(devStr,&netaddr,&netmask,errbuf);
  // printf("90 m %d\n",netmask);

  if(deScr == NULL ){
    // printf("91\n");
    return false;
  }
  return true;
}

bool Sniffer::closeNetDev()
{
  if(deScr != NULL){
    pcap_close(deScr);
    deScr = NULL;
    return true;
  }
  printf("there is no Net Device\n");
  return false;
}

void Sniffer::freeNetDevsMem()
{
	if (pAllNetDevs != NULL) {
		pcap_freealldevs(pAllNetDevs);
		pAllNetDevs = NULL;
	}
}

bool Sniffer::setDevsFilter(const char *szFilter)
{
  printf("%s\n",szFilter);
  struct bpf_program filter;

  // if ( pAllNetDevs->addresses != NULL ) {
	// 	netmask = ((struct sockaddr_in *)(pAllNetDevs->addresses->netmask))->sin_addr.s_addr;
	// } else {
	// 	netmask = 0xFFFFFF;		// 如果这个接口没有地址，那么我们假设这个接口在C类网络中
	// }
  if(pcap_compile(deScr,&filter,szFilter,1,netmask)<0){
    printf("err0 setComplie\n");
    return false;
  }
  if(pcap_setfilter(deScr,&filter)<0){
    printf("err0 setDevsFilter\n");
    return false;
  }

  return true;
}

int Sniffer::captureOnce()
{
  int res = pcap_next_ex(deScr, &pkthdr, &packet);

	return res;
}

bool Sniffer::captureByCallBack(C_B_fun func,u_char* user)
{
  if(deScr != NULL){
    pcap_loop(deScr,0,func,user);
    return true;
  }
  return false;
}

bool Sniffer::openDumpFile(const char *FileName)
{
  if(dumpFile != NULL){
    closeDumpFile();
  }
  if((dumpFile = pcap_dump_open(deScr,FileName)) != NULL){
    return true;
  }
  else return false;
}

void Sniffer::saveCaptureData(u_char *dumpFile,struct pcap_pkthdr *pkthdr,
                      u_char *packet)
{
  if(dumpFile!=NULL){
      pcap_dump(dumpFile,pkthdr,packet);
  }
}

void Sniffer::saveCaptureData()
{
  if(dumpFile!=NULL){
      pcap_dump((u_char *)dumpFile, pkthdr, packet);
  }
}

void Sniffer::closeDumpFile()
{
  if(dumpFile != NULL){
    pcap_dump_close(dumpFile);
    dumpFile = NULL;
  }
}

bool Sniffer::getNetDevInfo()
{
  if(pAllNetDevs == NULL){
    if(findAllNetDevs()==false){
      return false;
    }
  }

  pcap_if_t	*index;
  pcap_addr_t *pAddr;
  NetDevInfo cur;
  char ip6str[128];
  int i=1;
  for (index = pAllNetDevs; index != NULL; index = index->next) {
    cur.strDevId = i;
    ++i;
    cur.strNetDevname = index->name;

    if (index->description) {
      cur.strNetDevDescribe = index->description;
    } else {
      cur.strNetDevDescribe ="\tNo deScription available";
    }

    for (pAddr = index->addresses; pAddr != NULL; pAddr = pAddr->next) {
      switch(pAddr->addr->sa_family)
      {
      case AF_INET:

        cur.strIPV4FamilyName =  "\tAddress Family Name: AF_INET(IPV4)";

        if (pAddr->addr) {
          cur.strIPV4Addr=  "\tIPV4 Address:\t";
          cur.strIPV4Addr+=iptos(((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr);
        }
        if (pAddr->netmask) {
          cur.strNetmask = "\tNetmask:";
          cur.strNetmask+=iptos(((struct sockaddr_in *)pAddr->netmask)->sin_addr.s_addr);
        }
        if (pAddr->broadaddr) {
          cur.strBordAddr="\tBroadcast Address:";
          cur.strBordAddr+=iptos(((struct sockaddr_in *)pAddr->broadaddr)->sin_addr.s_addr);
        }
        if (pAddr->dstaddr) {
          cur.strDesAddr="\tDestination Address:";
            cur.strDesAddr+=iptos(((struct sockaddr_in *)pAddr->dstaddr)->sin_addr.s_addr);
        }
        break;
      case AF_INET6:
        cur.strIPV6FamilyName = "\tAddress Family Name : AF_INET6 (IPV6)";
      if (pAddr->addr) {
        cur.strIPV6Addr = " \tIPV6 Address : ";
        cur.strIPV6Addr += ip6tos(pAddr->addr, ip6str, sizeof(ip6str));
      }
        break;
      }
    }
    netDevsInfo.push_back(cur);
  }
}

void Sniffer::consolePrint()
{
    for (std::vector<NetDevInfo>::iterator index = netDevsInfo.begin();
    index < netDevsInfo.end(); ++index) {
      std::cout <<index->strDevId<<"."<<index->strNetDevname << "\n" << index->strNetDevDescribe << "\n"
      <<index->strIPV4FamilyName << "\n" << index->strIPV4Addr << "\n"
      <<index->strNetmask<<"\n"<<index->strBordAddr<<"\n"<<index->strDesAddr<<"\n"
      <<index->strIPV6FamilyName << "\n" << index->strIPV6Addr <<"\n"<< std::endl;
    }
}

void Sniffer::showSnifferData(SnifferData tmp){
  SnifferData *index=&tmp;
  std::cout<<"序号: "<<index->Id<<"\n"<<"时间: "<<index->strTime<<"\n"<<"数据长度:"<<index->Length<<"\n"
  <<"抓取长度："<<index->capLen<<"\n"<<"来源IP地址:"<<index->strSIP<<"\n"<<"目的IP地址:"<<index->strDIP<<"\n"
  <<"使用的协议:"<<index->strProto<<"\n"<<std::endl;

  std::cout<<index->protoInfo.strEthTitle<<"\n"<<index->protoInfo.strDMac<<"\n"<<index->protoInfo.strType<<"\n\n"<<index->protoInfo.strIPTitle<<"\n"
           <<index->protoInfo.strVersion<<"\n"<<index->protoInfo.strLength<<"\n"<<index->protoInfo.strNextProto<<"\n"<<index->protoInfo.strSIP<<"\n"
           <<index->protoInfo.strDIP<<"\n\n"<<index->protoInfo.strTranProto<<"\n"<<index->protoInfo.strSPort<<"\n"<<index->protoInfo.strDPort<<"\n\n"
           <<index->protoInfo.strAppProto<<"\n"<<std::endl;
}

void Sniffer::showSnifferData()
{
  for(std::vector<SnifferData>::iterator index=sniffersData.begin();
      index < sniffersData.end();++index){
        std::cout<<"序号: "<<index->Id<<"\n"<<"时间: "<<index->strTime<<"\n"<<"数据长度:"<<index->Length<<"\n"
        <<"抓取长度："<<index->capLen<<"\n"<<"来源IP地址:"<<index->strSIP<<"\n"<<"目的IP地址:"<<index->strDIP<<"\n"
        <<"使用的协议:"<<index->strProto<<"\n"<<std::endl;

        std::cout<<index->protoInfo.strEthTitle<<"\n"<<index->protoInfo.strDMac<<"\n"<<index->protoInfo.strType<<"\n\n"<<index->protoInfo.strIPTitle<<"\n"
                 <<index->protoInfo.strVersion<<"\n"<<index->protoInfo.strLength<<"\n"<<index->protoInfo.strNextProto<<"\n"<<index->protoInfo.strSIP<<"\n"
                 <<index->protoInfo.strDIP<<"\n\n"<<index->protoInfo.strTranProto<<"\n"<<index->protoInfo.strSPort<<"\n"<<index->protoInfo.strDPort<<"\n\n"
                 <<index->protoInfo.strAppProto<<"\n"<<std::endl;
      }
}

void Sniffer::showQQnum()
{
  printf("showQQnum\n");
  for(std::vector<QQ>::iterator index=QQnum.begin();
      index < QQnum.end();++index){
        std::cout<<"qq号："<<index->qq_num<<"\n"<<std::endl;
      }
}

char *Sniffer::iptos(u_long in)
{
  static char output[IPTOSBUFFERS_1][3*4+3+1];
  static short which;
  u_char *p;

  p = (u_char *)&in;
  which = (which + 1 == IPTOSBUFFERS_1 ? 0 : which + 1);
  sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

  return output[which];
}

char *Sniffer::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    	socklen_t sockaddrlen;

    	sockaddrlen = sizeof(struct sockaddr_in6);

    	sockaddrlen = sizeof(struct sockaddr_storage);

    	if (getnameinfo(sockaddr, sockaddrlen, address, addrlen, NULL, 0, NI_NUMERICHOST) != 0) {
    		address = NULL;
    	}

    	return address;
}
