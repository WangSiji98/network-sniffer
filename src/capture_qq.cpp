/*
=====================================================================
    Filename:capture_qq.h
    Author：Siji
    deScription: 网络数据包抓取类的类实现文件
=====================================================================
*/


#include"../include/sniffer.h"
#include"../include/headerType.h"
#include"../include/capture_qq.h"
#include<time.h>
#include<string>

Capture_qq::Capture_qq()
{
  sniffer = NULL;
  flag_run=true;
  Filename = NULL;
}

Capture_qq::Capture_qq(Sniffer *pSniffer,char *filename)
{
  sniffer = pSniffer;
  flag_run= true;
  Filename =filename;
}

Capture_qq::~Capture_qq(){
}

void Capture_qq::setNetDev()
{
  sniffer-> findAllNetDevs();
  sniffer-> getNetDevInfo();
  sniffer->openNetDev(1);
}

void Capture_qq::run()
{
  int res;
  struct tm *ltime;
  time_t local_tv_sec;
  char   timestr[16];

  QQ tmp;

  int num =1;
  sniffer->QQnum.clear();

  while(flag_run==true&&(res=sniffer->captureOnce())>=0){
    if(res == 0){
      continue;
    }
    if(num>10) break;
    eth_header *eh;
    ip_header *ih;
    udp_header *uh;
    tcp_header *th;
    unsigned short sport,dport;
    unsigned int ip_len;
    unsigned char   *pByte;

    //获得 IP 协议头
    ih = (ip_header *)(sniffer->packet+14);

    //获取 ip 首部长度
    ip_len=ih->ihl*4;
    unsigned int QQnumber;


    if (ih->proto == UDP_SIG) {
        uh = (udp_header *)((unsigned char *)ih + ip_len);      // 获得 UDP 协议头
        sport = ntohs(uh->src_port);                               // 获得源端口和目的端口
        dport = ntohs(uh->dst_port);
        pByte = (unsigned char *)ih + ip_len + sizeof(udp_header);
        if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT)) {
              QQnumber = *(int *)(pByte + QQ_NUM_OFFSET);
              tmp.qq_num = QQnumber;
            }
        else{
          continue;
          }
          num++;
        QQnumber = ntohl(QQnumber);

        if(QQnumber == 0){
          continue;
        }
    }
    else{
      continue;
    }

    char szQQNumber[12],szSaddr[24], szDaddr[24];
    sprintf(szQQNumber,"%u",QQnumber);
    sprintf(szSaddr, "%d.%d.%d.%d", ih->ip_src[0], ih->ip_src[1], ih->ip_src[2], ih->ip_src[3]);
    sprintf(szDaddr, "%d.%d.%d.%d", ih->ip_dst[0], ih->ip_dst[1], ih->ip_dst[2], ih->ip_dst[3]);

    if (flag_run == false) {
				return;
			}

    printf("%u\n",QQnumber);
    sniffer->QQnum.push_back(tmp);
  }
    sniffer->showQQnum();
}

void Capture_qq::stop()
{
  flag_run = true;
}
