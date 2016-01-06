#ifndef __MD5_FUNC_H__
#define __MD5_FUNC_H__

#include <windows.h>

typedef struct {
	unsigned long count[2];
	unsigned long state[4];
	unsigned char buffer[64];
	unsigned char result[16];
}MD5_CTX;

typedef void (CALLBACK* MD5Init_T)(MD5_CTX *);
typedef void (CALLBACK* MD5Update_T)(MD5_CTX *, unsigned char *, unsigned int);
typedef void (CALLBACK* MD5Final_T)(MD5_CTX *);

void CalculateMD5(unsigned char,unsigned char*, int, unsigned char*, int, unsigned char*);
bool LoadMD5Func(HINSTANCE*, MD5Init_T*, MD5Update_T*, MD5Final_T*);

#endif