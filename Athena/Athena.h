#include "resource.h"
#include <stdio.h>
#include "pcap.h"
#include <Windowsx.h>
#include <iphlpapi.h>
#include <Commctrl.h>
#include "md5.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

typedef struct {
	pcap_if  *d;
	char     usr[32];
	char     pwd[32];
}T_PRAM;
struct CFG{
	char     usr[32];
	char     pwd[32];
    bool     isLAN;
};
typedef struct Authentication{
	unsigned char  dst[6];      // \x01\x80\xc2\x00\x00\x03
	unsigned char  src[6];      // \x60\xeb\x69\x55\x7e\xc9
	unsigned char  proto[2];    // 0x888e-802.1X Authentication
	unsigned char  ver;         // 02-802.1X-2004
	unsigned char  type;        // EAP Packet(00);Start(01);Logoff(02)
	unsigned short length;
}AUTH_HDR;//12
typedef struct Authen_exten{
	unsigned char  code;        // Request(1);Response(2);Success(3);Failure(4)
	unsigned char  id;          // (1);(2)
	unsigned short length;
	unsigned char  type;        // Identity(1);Md5-Challenge(4)
	unsigned char  nouse[3];    // ×Ö½Ú¶ÔÆë
	unsigned char* identity;
}AUTH_EXT;