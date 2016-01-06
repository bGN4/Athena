#pragma  comment(linker,"/OPT:NOWIN98")
#include "md5.h"
extern   MD5Init_T   MD5Init;
extern   MD5Final_T  MD5Final;
extern   MD5Update_T MD5Update;
void CalculateMD5(unsigned char c,unsigned char *pwd, int pwdlen, unsigned char *chp, int chplen, unsigned char *result) {
	MD5_CTX m;
	unsigned char *buf = (unsigned char*)malloc((1+pwdlen+chplen+1)*sizeof(unsigned char));
	memcpy(buf + 0x00, &c, 1);
	memcpy(buf + 0x01, pwd, pwdlen);
	memcpy(buf + 0x01 + pwdlen, chp, chplen);
	memcpy(buf + 0x01 + pwdlen + chplen, "\x00", 1);
	MD5Init(&m);
	MD5Update(&m,buf,strlen((char*)buf));
	MD5Final(&m);
	memcpy(result,m.result,16);
	memcpy(result + 0x10, "\x00", 1);
	free(buf);
}
bool LoadMD5Func(HINSTANCE *Cryptdll, MD5Init_T *MD5Init, MD5Update_T *MD5Update, MD5Final_T *MD5Final) {
	*Cryptdll = LoadLibrary("Cryptdll.dll");
	if(*Cryptdll == NULL) {
		MessageBox(NULL,"Failed to load Cryptdll.dll","LoadLibrary()",MB_OK);
		return false;
	}
	*MD5Init   = (MD5Init_T)   GetProcAddress(*Cryptdll, "MD5Init");
	*MD5Update = (MD5Update_T) GetProcAddress(*Cryptdll, "MD5Update");
	*MD5Final  = (MD5Final_T)  GetProcAddress(*Cryptdll, "MD5Final");
	if (*MD5Init == NULL || *MD5Update == NULL || *MD5Final == NULL) {
		MessageBox(NULL,"Failed to Load the Encryption function.","GetProcAddress()",MB_OK);
		FreeLibrary(*Cryptdll);
		return false;
	}
	return true;
}