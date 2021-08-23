/*
=====================================================================
    Filename:capture.h
    Author：Siji
    deScription: 网络数据包抓取类的类实现文件
=====================================================================
*/

#include"../include/capture.h"
#include"../include/sniffer.h"
#include"../include/headerType.h"

#include<time.h>
#include<string>

Capture::Capture()
{
  sniffer = NULL;
  flag_run=true;
  Filename = NULL;
}

Capture::Capture(Sniffer *pSniffer,char *filename)
{
  sniffer = pSniffer;
  flag_run= true;
  Filename =filename;
}

Capture::~Capture(){
}

void Capture::setNetDev()
{
  sniffer-> findAllNetDevs();
  sniffer-> getNetDevInfo();
  sniffer->openNetDev(1);
}

void Capture::run()
{
  int res;
  struct tm *ltime;
  time_t local_tv_sec;
  char   timestr[16];

  SnifferData tmp;

  int num =1;
  sniffer->sniffersData.clear();
  // printf("%s\n",Filename);

  if(Filename!=NULL){
    sniffer->openDumpFile(Filename);
  }

  while(flag_run==true&&(res=sniffer->captureOnce())>=0){
    if(res == 0){
      continue;
    }
    sniffer->saveCaptureData();

    tmp.protoInfo.init();

    tmp.Id=num;
    num++;
    printf("%d\n",num);
    if(num>4) break;
    tmp.strTime = ctime((const time_t *)&(sniffer->pkthdr)->ts.tv_sec);

    tmp.Length = sniffer->pkthdr->len;

    tmp.capLen = sniffer->pkthdr->caplen;

    eth_header *eh;
    ip_header *ih;
    udp_header *uh;
    tcp_header *th;
    unsigned short sport,dport;
    unsigned int ip_len,ip_all_len;
    unsigned char   *pByte;
    // std::string str="";
    // 获得 Mac头
    eh = (eth_header *)sniffer->packet;
    char buf1[20],buf2[20];

    sprintf(buf1,"%02x-%02x-%02x-%02x-%02x-%02x",eh->mac_dst[0],eh->mac_dst[1],eh->mac_dst[2],eh->mac_dst[3],eh->mac_dst[4],eh->mac_dst[5]);
    tmp.protoInfo.strDMac =tmp.protoInfo.strDMac+buf1;

    sprintf(buf2,"%02x-%02x-%02x-%02x-%02x-%02x",eh->mac_src[0],eh->mac_src[1],eh->mac_src[2],eh->mac_src[3],eh->mac_src[4],eh->mac_src[5]);
    tmp.protoInfo.strSMac =tmp.protoInfo.strSMac+buf2;

    //获得 IP 协议头
    ih = (ip_header *)(sniffer->packet+14);

    //获取 ip 首部长度
    ip_len=ih->ihl*4;

    char szSize[6];
    sprintf(szSize, "%u", ip_len);
    tmp.protoInfo.strHeadLength += szSize;
    tmp.protoInfo.strHeadLength += " bytes";

    ip_all_len = ntohs(ih->t_len);
    sprintf(szSize, "%u", ip_all_len);
    tmp.protoInfo.strLength += szSize;
    tmp.protoInfo.strLength += " bytes";

    char szSaddr[24], szDaddr[24];
    sprintf(szSaddr, "%d.%d.%d.%d", ih->ip_src[0], ih->ip_src[1], ih->ip_src[2], ih->ip_src[3]);
    sprintf(szDaddr, "%d.%d.%d.%d", ih->ip_dst[0], ih->ip_dst[1], ih->ip_dst[2], ih->ip_dst[3]);

    switch (ih->proto) {
        case TCP_SIG:
            tmp.strProto = "TCP";
            tmp.protoInfo.strNextProto += "TCP (Transmission Control Protocol)";
            tmp.protoInfo.strTranProto += "TCP 协议 (Transmission Control Protocol)";
            th = (tcp_header *)((unsigned char *)ih + ip_len);      // 获得 TCP 协议头
            sport = ntohs(th->src_port);                               // 获得源端口和目的端口
            dport = ntohs(th->dst_port);

            if (sport == FTP_PORT || dport == FTP_PORT) {
                tmp.strProto += " (FTP)";
                tmp.protoInfo.strAppProto += "FTP (File Transfer Protocol)";
            } else if (sport == TELNET_PORT || dport == TELNET_PORT) {
                tmp.strProto += " (TELNET)";
                tmp.protoInfo.strAppProto += "TELNET";
            } else if (sport == SMTP_PORT || dport == SMTP_PORT) {
                tmp.strProto += " (SMTP)";
                tmp.protoInfo.strAppProto += "SMTP (Simple Message Transfer Protocol)";
            } else if (sport == POP3_PORT || dport == POP3_PORT) {
                tmp.strProto += " (POP3)";
                tmp.protoInfo.strAppProto += "POP3 (Post Office Protocol 3)";
            } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
                tmp.strProto += " (HTTPS)";
                tmp.protoInfo.strAppProto += "HTTPS (Hypertext Transfer "
                                                        "Protocol over Secure Socket Layer)";
            } else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                     sport == HTTP2_PORT || dport == HTTP2_PORT) {
                tmp.strProto += " (HTTP)";
                tmp.protoInfo.strAppProto += "HTTP (Hyper Text Transport Protocol)";
                //tmp.protoInfo.strSendInfo = rawByteData.remove(0, 54);
            } else {
                tmp.protoInfo.strAppProto += "Unknown Proto";
            }
            break;
        case UDP_SIG:
            tmp.strProto = "UDP";
            tmp.protoInfo.strNextProto += "UDP (User Datagram Protocol)";
            tmp.protoInfo.strTranProto += "UDP 协议 (User Datagram Protocol)";
            uh = (udp_header *)((unsigned char *)ih + ip_len);      // 获得 UDP 协议头
            sport = ntohs(uh->src_port);                               // 获得源端口和目的端口
            dport = ntohs(uh->dst_port);
            pByte = (unsigned char *)ih + ip_len + sizeof(udp_header);

            if (sport == DNS_PORT || dport == DNS_PORT) {
                tmp.strProto += " (DNS)";
                tmp.protoInfo.strAppProto += "DNS (Domain Name Server)";
            } else if (sport == SNMP_PORT || dport == SNMP_PORT) {
                tmp.strProto += " (SNMP)";
                tmp.protoInfo.strAppProto += "SNMP (Simple Network Management Protocol)";
            } else if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT)) {
                tmp.strProto += " (QQ)";
            } else {
                tmp.protoInfo.strAppProto += "Unknown Proto";
            }
            break;
        default:
            continue;
        }

    char szSPort[6], szDPort[6];
    sprintf(szSPort, "%d", sport);
    sprintf(szDPort, "%d", dport);

    tmp.strSIP = szSaddr;
    tmp.strSIP = tmp.strSIP + " : " + szSPort;
    tmp.strDIP = szDaddr;
    tmp.strDIP = tmp.strDIP + " : " + szDPort;

    tmp.protoInfo.strSIP   += szSaddr;
    tmp.protoInfo.strDIP   += szDaddr;
    tmp.protoInfo.strSPort += szSPort;
    tmp.protoInfo.strDPort += szDPort;
    // sniffer->showSnifferData(tmp);
    sniffer->sniffersData.push_back(tmp);
  }
    sniffer->showSnifferData();
}

void Capture::stop()
{
  flag_run=true;
}

void toHex(u_char *tmp,char *buf)
{
    sprintf(buf,"%02x-%02x-%02x-%02x-%02x-%02x",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);
}
