#pragma once
#include"stdafx.h"
#include<string>
#include<map>
#include<zlib\zlib.h>

#ifdef _DEBUG
#pragma comment(lib, "Debug\\zdll.lib")
#else
#pragma comment(lib, "Release\\zdll.lib")
#endif


#define BUF_SIZE 65535

bool wx_stackreport_complete(std::map<std::string, std::string>& mapresult,const http::BufferedRequest &request);