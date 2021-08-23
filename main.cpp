#include<stdio.h>
#include "./include/capture.h"
#include "./include/sniffer.h"
#include "./include/capture_qq.h"

int main(){
  Sniffer *s0=new Sniffer;
  Capture t0(s0,"./c_data/out4.pcap");
  t0.setNetDev();
  s0->consolePrint();
  printf("%s\n",s0->devStr);
  //s0->setDevsFilter("src host 192.168.1.110");
  // s0->setDevsFilter("src host 192.168.1.108||dst host ==192.168.1.108");
  t0.run();
  t0.stop();
  // Sniffer S0;
  // S0.findAllNetDevs();
  // S0.getNetDevInfo();
  // S0.consolePrint();
  // S0.openNetDev(1);
  // if(!S0.setDevsFilter("(tcp[13]==0x10) or (tcp[13]==0x18)")){
  //   S0.closeNetDev();
  //   printf("setDevsFilter error\n");
  //   return -1;
  // };
  // S0.captureOnce();
  // eth_header *eh;
  // S0.openDumpFile("./c_data/out2.pcap");
  // printf("%s\n",S0.devStr);
  //
  // S0.saveCaptureData();
  //
  // S0.closeDumpFile();
  //
  // S0.captureOnce();
  // S0.closeNetDev();

}
