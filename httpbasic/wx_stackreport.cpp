#include"stdafx.h"
#include"wx_stackreport.h"
#include<httpxx/Url.hpp>

//b(j paramj1, j paramj2, int paramInt)
void keyexpend_one(char *keybuffer, char *key, int paramInt)
{
	for (int i = 0; i < paramInt; i++)
		keybuffer[i] = ((char)(0x1 & key[(i >> 3)] >> (i & 0x7)));
}

//a(j paramj1, j paramj2, byte[] paramArrayOfByte, int paramInt, j paramj3)
void keyexpend_two(char *localbuffer1, char *localbuffer2, char *paramArrayOfByte, int paramInt, char *localbuffer3)
{
	for (int i = 0; i < paramInt; i++)
		localbuffer3[i] = localbuffer2[(-1 + paramArrayOfByte[i])];
	memcpy(localbuffer1, localbuffer3, paramInt);
}

void keyexpend_three(char *keybuffer1, char *keybuffer2, int paramInt)
{
	memcpy(keybuffer2, keybuffer1, paramInt);
	for (int i = 0; i<28 - paramInt; i++)
	{
		keybuffer1[i] = keybuffer1[paramInt + i];
	}
	int k = 0;
	while (k < paramInt)
	{
		keybuffer1[(28 + k - paramInt)] = keybuffer2[k];
		k++;
	}
}

bool decryptfirst(char data[16][48], char *localbuffer1, char *key, int keylen, char *localbuffer2, char *localbuffer3, char *localbuffer4, char *localbuffer5)
{
	if (keylen > 24) keylen = 24;
	memcpy(localbuffer1, key, keylen);
	char arrayOfByte1[] = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
	char arrayOfByte2[] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
	char arrayOfByte3[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	keyexpend_one(localbuffer3, key, 64);
	keyexpend_two(localbuffer3, localbuffer3, arrayOfByte1, 56, localbuffer5);
	for (int i = 0; i < 16; i++)
	{
		keyexpend_three(localbuffer3, localbuffer5, arrayOfByte3[i]);
		keyexpend_three(localbuffer4, localbuffer5, arrayOfByte3[i]);
		keyexpend_two(data[i], localbuffer3, arrayOfByte2, 48, localbuffer5);
	}
	return true;
}

//a(j paramj1, j paramj2, int paramInt)
void decrypt_xor(char *localbuffer1, char *localbuffer2, int paramInt)
{
	for (int i = 0; i < paramInt; i++)
	{
		localbuffer1[i] = (localbuffer1[i] ^ localbuffer2[i]);
	}
}

//a(j paramj1, j paramj2, j paramj3)
void decrypt_xor(char *localbuffer1, char *localbuffer2, char *localbuffer3)
{
	for (int i = 0; i < 8; i++)
		localbuffer1[i] = ((localbuffer2[i] ^ localbuffer3[i]));
}

//a(j paramj1, j paramj2, j paramj3, j paramj4)
void sbox_expand(char *localbuffer1, char *localbuffer2, char *localbuffer3, char *localbuffer4)
{
	char ExtendedETable[] =
	{ 32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12,
		13, 12, 13, 14, 15,
		16, 17, 16, 17, 18,
		19, 20, 21, 20, 21,
		22, 23, 24, 25, 24,
		25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1
	};
	char PTable[] =
	{ 16, 7, 20, 21, 29, 12,
		28, 17, 1, 15, 23, 26,
		5, 18, 31, 10, 2, 8,
		24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11,
		4, 25 };
	keyexpend_two(localbuffer3, localbuffer1, ExtendedETable, 48, localbuffer4);
	decrypt_xor(localbuffer3, localbuffer2, 48);
	char SBox[][4][16] = {
		{
			{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
			{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
			{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
			{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
			{
				{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
				{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
				{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
				{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
			},
			{
				{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
				{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
				{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
				{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
			},
			{
				{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
				{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
				{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
				{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
			},
			{
				{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
				{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
				{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
				{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
			},
			{
				{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
				{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
				{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
				{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
			},
			{
				{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
				{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
				{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
				{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
			},
			{
				{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
				{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
				{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
				{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
			}
	};
	int j = 0;
	int k = 0;
	int i = 0;
	while (i < 8)
	{
		int m = (localbuffer3[j] << 1) + localbuffer3[5 + j];
		int n = ((localbuffer3[(1 + j)] << 3) + (localbuffer3[(2 + j)] << 2) + (localbuffer3[(3 + j)] << 1) + localbuffer3[(4 + j)]);
		keyexpend_one(localbuffer1 + k, &(SBox[i][m][n]), 4);
		i = i + 1;
		j = (6 + j);
		k = (4 + k);
	}
	keyexpend_two(localbuffer1, localbuffer1, PTable, 32, localbuffer4);
}

bool decryptsecond(char *localbuffer1, char *localbuffer2, char data[16][48], int paramInt, char *localbuffer3, char *localbuffer4, char *localbuffer5, char *localbuffer6, char *localbuffer7, char *localbuffer8)
{
	char IPTable[] = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};
	char RIPTable[] = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25
	};
	keyexpend_one(localbuffer3, localbuffer2, 64);
	keyexpend_two(localbuffer3, localbuffer3, IPTable, 64, localbuffer8);
	for (int i = 15; i >= 0; i--)
	{
		memcpy(localbuffer5, localbuffer6, 32);
		sbox_expand(localbuffer6, data[i], localbuffer4, localbuffer8);
		decrypt_xor(localbuffer6, localbuffer7, 32);
		memcpy(localbuffer7, localbuffer5, 32);
	}
	keyexpend_two(localbuffer3, localbuffer3, RIPTable, 64, localbuffer8);
	memset(localbuffer1, 0, 8);
	for (int j = 0; j < 64; j++)
	{
		int k = j >> 3;
		localbuffer1[k] = localbuffer1[k] | localbuffer3[j] << (j & 0x7);
	}

	return true;
}

bool wechat_support_decrypt(char* dstbuffer, int dstlen, char* srcbuffer, int srclen, int keylen, char* key, int mode)
{
	char data[16][48] = { 0 };
	char *localbuffer2 = srcbuffer;
	char localbuffer3[256] = { 0 };
	char localbuffer4[24] = { 0 };
	char localbuffer5[64] = { 0 };
	char *localbuffer6 = localbuffer5;
	char *localbuffer7 = localbuffer5 + 28;
	char localbuffer10[64] = { 0 };
	char *localbuffer8 = localbuffer10;
	char *localbuffer9 = localbuffer10 + 32;
	char localbuffer11[48] = { 0 };
	char localbuffer12[32] = { 0 };
	char localbuffer13[9] = { 0 };
	char localbuffer14[8] = { 0 };

	long l1 = 0;
	if ((srcbuffer != 0) && (srclen > 0))
	{
		l1 = 0xFFFFFFF8 & 7L + srclen;
	}
	else
	{
		return false;
	}
	if (l1)
	{
		decryptfirst(data, localbuffer4, key, keylen, localbuffer5, localbuffer6, localbuffer7, localbuffer3);
		//½âÃÜ
		decryptsecond(dstbuffer, localbuffer13, data, mode, localbuffer10, localbuffer11, localbuffer12, localbuffer8, localbuffer9, localbuffer3);
		memcpy(localbuffer13, localbuffer2, 8);
		long l2 = 1L;
		long l3 = l1 >> 3;
		int i = 0;
		int j = 8;
		while (true)
		{
			if (l2<l3)
			{
				decryptsecond(localbuffer14, localbuffer2 + j, data, mode, localbuffer10, localbuffer11, localbuffer12, localbuffer8, localbuffer9, localbuffer3);
				decrypt_xor(dstbuffer + i, localbuffer14, localbuffer13);
				memcpy(localbuffer13, localbuffer2 + j, 8);
				l2 += 1L;
				i += 8;
				j += 8;
			}
			else
				break;
		}
	}
	return true;
}

int _zdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream; /* decompression stream */
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if (inflateInit(&d_stream) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if (err != Z_OK) return -1;
	}
	if (inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}

int zdecompress(Byte *zdata, uLong nzdata, Bytef *odata, uLong dstLen)
{
	memset(odata, 0, dstLen);
	uLong nodata = dstLen;
	return _zdecompress(zdata, nzdata, odata, &nodata);
};

bool wx_stackreport_very_sign(std::map<std::string, std::string>& mapresult,const http::BufferedRequest &request)
{
	const std::string sigurl = "/cgi-bin/mmsupport-bin/stackreport?";
	std::string sighost="support.weixin.qq.com";

	if (request.header("Host") == sighost)
	{
		std::string url = request.url();
		if (url.find(sigurl) != -1)
			return true;
	}
	return false;
}

bool wx_stackreport_complete(std::map<std::string, std::string>& mapresult, const http::BufferedRequest &request)
{
	if (!wx_stackreport_very_sign(mapresult, request))
		return false;
	std::string url=request.url();
	std::string key;
	if (url.size())
	{
		size_t pos= url.find("sum=");
		std::string str = url.substr(pos + 4);
		pos=str.find_first_of("&");
		key = str.substr(0, pos);
	}
	std::string reporttype;
	if (url.size())
	{
		size_t pos = url.find("reporttype=");
		std::string str = url.substr(pos + 11);
		pos = str.find_first_of("&");
		reporttype = str.substr(0, pos);
	}
	std::string NewReportType;
	if (url.size())
	{
		size_t pos = url.find("NewReportType=");
		std::string str = url.substr(pos + 14);
		pos = str.find_first_of("&");
		NewReportType = str.substr(0, pos);
	}
	unsigned char *srcbuffer =(unsigned char *)(request.body().c_str());
	unsigned int srclen = request.body().size();
	unsigned int dstlen = srclen;
	char *dstbuffer = (char*)malloc(dstlen);
	memset(dstbuffer, 0, dstlen);
	wechat_support_decrypt(dstbuffer, dstlen, (char*)srcbuffer, srclen, key.size(), (char*)(key.c_str()), 1);
	Bytef *odata = (Bytef*)malloc(dstlen * 2);
	zdecompress((Byte*)dstbuffer, dstlen, odata, dstlen * 2);
	std::string body;
	body.append((char*)odata, strlen((char*)odata));
	unsigned int number = mapresult.size();
	mapresult.insert(std::pair<std::string, std::string>(SurrealDebugLog::string_format("decbody-%d-%s-%s", number, reporttype.c_str(), NewReportType.c_str()), body));
	free(odata);
	odata = 0;
	free(dstbuffer);
	dstbuffer = 0;
	return true;
}