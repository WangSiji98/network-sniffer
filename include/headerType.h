/*
=====================================================================
    Filename:headerType.h
    Author：Siji
    Description: 定义一些协议头部结构体和常量的头文件
=====================================================================
*/

#ifndef HEADERTYPE_H_
#define HEADERTYPE_H_

 #include<iostream>
#include<string>
// 数据链路层

#define QQ_SIGN			('\x02')	// OICQ协议标识
#define QQ_SER_PORT		(8000)		// QQ服务器所用端口号
#define QQ_NUM_OFFSET	(7)			// QQ号码信息在QQ协议头中的偏移

//Mac头部(14 Bytes)
typedef struct _eth_header
{
  unsigned char mac_dst[6]; //目标mac地址(6 Bytes)
  unsigned char mac_src[6]; //来源mac地址(6 Bytes)
  unsigned short eth_type;  //以太网类型(2 Bytes)
}eth_header;

//ARP头部(28 Bytes)
typedef struct _arphdr_header
{
  u_int16_t arp_htype; //硬件类型 (2 Bytes)
  u_int16_t arp_ptype; //协议类型 (2 Bytes)
  u_char arp_hlen; //硬件地址长度 (1 Byte)
  u_char arp_plen; //协议地址长度 (1 Byte)
  u_int16_t arp_oper; //ARP操作类型 (2 Bytes)
  u_char src_sha[6];//发送者硬件地址 (6 Bytes)
  u_char src_spa[4];//发送者协议地址 (4 Bytes)
  u_char dst_tha[6];//目标硬件地址 (6 Bytes)
  u_char dst_tpa[4];//目标协议地址 (4 Bytes)
}arphdr_header;

// 网络层

//      IP协议      协议号
#define IP_SIG			(0)
#define ICMP_SIG		(1)
#define IGMP_SIG		(2)
#define GGP_SIG			(3)
#define IP_ENCAP_SIG	(4)
#define ST_SIG			(5)
#define TCP_SIG			(6)
#define EGP_SIG			(8)
#define PUP_SIG			(12)
#define UDP_SIG			(17)
#define HMP_SIG			(20)
#define XNS_IDP_SIG		(22)
#define RDP_SIG			(27)
#define TP4_SIG			(29)
#define XTP_SIG			(36)
#define DDP_SIG			(37)
#define IDPR_CMTP_SIG	(39)
#define RSPF_SIG		(73)
#define VMTP_SIG		(81)
#define OSPFIGP_SIG		(89)
#define IPIP_SIG		(94)
#define ENCAP_SIG		(98)

//IPv4 头部(20 Bytes)
typedef struct _ip_header
{
  unsigned char ver:4;//版本(4 bites）)
  unsigned char ihl:4; //首部长度(4 bites)
  unsigned char ser_type; //服务类型(1 Byte)
  unsigned short t_len; //总长 (2 Bytes)
  unsigned short iden; //标识 (2 Bytes)
  unsigned short flags:3; //标志位(3 bites)
  unsigned short offset:13; //片偏移量(13 bites)
  unsigned char ttl; //生存时间 (1 Byte)
  unsigned char proto; //协议 ( 1 Byte)
  unsigned short crc; //首部校验和 (2 Bytes)
  unsigned char ip_src[4]; //源地址 (4 Bytes)
  unsigned char ip_dst[4]; //目标地址 (4 Bytes)
}ip_header;

// 传输层

// TCP头部（20 Bytes）
typedef struct _tcp_header
{
	unsigned short	src_port;				// 源端口号(2 Bytes)
	unsigned short	dst_port;				// 目的端口号(2 Bytes)
	unsigned int	tcp_seq;				// 序列号 (4 Bytes)
	unsigned int	tcp_ack;				// 确认号 (4 Bytes)
	unsigned char	tcp_hl:4;				// tcp头部长度 (4 bites)
	unsigned char	reserved_1:4;		// 保留6位中的4位首部长度 (4bites)
	unsigned char	reseverd_2:2;		// 保留6位中的2位(2 bites)
	unsigned char	flag:6;				// 6位标志 (6 bites)
	unsigned short	wnd_size;			// 16位窗口大小 (2 Bytes)
	unsigned short	chk_sum;			// 16位TCP检验和(2 Bytes)
	unsigned short	urgt_p;				// 16为紧急指针(s Bytes)
}tcp_header;

// UDP头部（8字节）
typedef struct _udp_header
{
	unsigned short	src_port;		// 源端口
	unsigned short	dst_port;		// 目的端口
	unsigned short	len;		// UDP数据包长度
	unsigned short	crc;		// 校验和
}udp_header;

// 应用层

// 定义一些应用层协议使用的端口号

// TCP 协议
#define FTP_PORT 		(21) //文件传输协议端口
#define TELNET_PORT 	(23) //远程终端协议端口
#define SMTP_PORT 		(25) //简单邮件传送协议端口
#define HTTP_PORT  		(80) //超文本传送协议端口
#define HTTPS_PORT		(443)  //安全超文本传输​​协议
#define HTTP2_PORT 		(8080) //超文本传输协议 2.0 端口
#define POP3_PORT 		(110)  //邮局协议版本3端口

// UDP 协议
#define DNS_PORT		(53) //域名系统端口
#define SNMP_PORT		(161) //简单网络管理协议端口

// 网络设备信息结构
struct NetDevInfo
{
  int strDevId;
	std::string strNetDevname;
	std::string strNetDevDescribe;
	std::string strIPV4FamilyName;
  std::string strIPV4Addr;
  std::string strNetmask;
  std::string strBordAddr;
  std::string strDesAddr;
	std::string strIPV6FamilyName;
	std::string strIPV6Addr;
};

// 树形显示结果的数据结构
struct AnalyseProtoType
{
	std::string 	strEthTitle;		// 数据链路层
	std::string 	strDMac;
	std::string 	strSMac;
	std::string 	strType;

	std::string 	strIPTitle;			// 网络层
	std::string 	strVersion;
	std::string 	strHeadLength;
	std::string 	strLength;
	std::string 	strNextProto;
	std::string 	strSIP;
	std::string 	strDIP;

	std::string 	strTranProto;		// 传输层
	std::string 	strSPort;
	std::string 	strDPort;

	std::string 	strAppProto;		// 应用层
	//QByteArray  strSendInfo;

	void init()
	{
		strEthTitle   = "数据链路层 - Ethrmet II";
		strDMac       = "目标MAC地址：";
		strSMac       = "来源MAC地址：";
		strType       = "以太网类型：Internet Protocol (0x0800)";

		strIPTitle    = "网络层 - IP 协议 (Internet Protocol)";
		strVersion    = "版本：IPv4";
		strHeadLength = "协议头长度：";
		strLength     = "总长：";
		strNextProto  = "高层协议类型：";
		strSIP        = "来源IP地址：";
		strDIP        = "目标IP地址：";

		strTranProto  = "传输层 - ";
		strSPort      = "来源端口号：";
		strDPort      = "目标端口号：";

		strAppProto   = "应用层 - ";
	}
};

// 捕获的数据结构
struct SnifferData
{
	int	Id;			// 序号
	std::string	strTime;		// 时间
  int  Length;		// 数据长度
  int capLen; //抓取数字长度
	std::string 			strSIP;			// 来源 IP 地址，格式 IP:port
	std::string 			strDIP;			// 目标 IP 地址，格式 IP:port
	std::string 			strProto;		// 使用的协议
	//QByteArray  		strData;		// 原始数据
	AnalyseProtoType	protoInfo;		// 树形显示结果的数据结构
};

struct QQ{
  unsigned short qq_num;
};

#endif //HEADERTYPE_H_
