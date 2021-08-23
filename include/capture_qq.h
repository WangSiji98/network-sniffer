/*
=====================================================================
    Filename:capture.h
    Author： Siji
    deScription:  捕获QQ数据的类声明文件
=====================================================================
*/

#ifndef CAPTUREQQ_H_
#define CAPTUREQQ_H_

#include "sniffer.h"
#include "headerType.h"
#include<time.h>
#include<string>

class Capture_qq
{
  public:
    Capture_qq();
    Capture_qq(Sniffer* pSniffer,char *filename);
    ~Capture_qq();
    void setNetDev();//设置设备信息
    void run();//开始抓取数据
    void stop();//停止抓取数据

  private:
    Sniffer *sniffer;
    bool flag_run;
    char *Filename;
};

#endif //CAPTURE_H_
