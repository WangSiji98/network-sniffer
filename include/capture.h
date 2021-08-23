/*
=====================================================================
    Filename:capture.h
    Author： Siji
    deScription: 网络数据包抓取类的类声明文件
=====================================================================
*/

#ifndef CAPTURE_H_
#define CAPTURE_H_

#include "sniffer.h"
#include "headerType.h"

class Capture
{
  public:
    Capture();
    Capture(Sniffer* pSniffer,char *filename);
    ~Capture();
    void setNetDev();//设置设备信息
    void run();//开始抓取数据
    void stop();//停止抓取数据

  private:
    Sniffer *sniffer;
    bool flag_run;
    char *Filename;
    void toHex(u_char *tmp,char *buf);
};

#endif //CAPTURE_H_
