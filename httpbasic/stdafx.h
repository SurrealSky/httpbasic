// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头中排除极少使用的资料
// Windows 头文件: 
#include <windows.h>



// TODO:  在此处引用程序需要的其他头文件
#include<plugin\pluginapi.h>

#ifdef _DEBUG
#pragma comment(lib, "Debug\\CorePlugin.lib")
#else
#pragma comment(lib, "Release\\CorePlugin.lib")
#endif

#include<LogLib\DebugLog.h>

//#include"../MemoryPool/MemMgr.h"
//using namespace SurrealMemMgr;

//#ifdef _DEBUG
//#pragma comment(lib, "..\\Debug\\MemMgr.lib")
//#else
//#pragma comment(lib, "..\\Release\\MemMgr.lib")
//#endif

//#include<pcapplusplus19.12\IPv4Layer.h>
//#include<pcapplusplus19.12\IPv6Layer.h>
//#include<pcapplusplus19.12\Packet.h>
//#include<pcapplusplus19.12\PcapFileDevice.h>
//#include<pcapplusplus19.12\TcpReassembly.h>
//#include<pcapplusplus19.12\PcapLiveDevice.h>
//#include<pcapplusplus19.12\LRUList.h>
//#include<pcapplusplus19.12\PcapLiveDeviceList.h>
//#include<pcapplusplus19.12\IpUtils.h>
//#include<pcapplusplus19.12\SystemUtils.h>
//#include<pcapplusplus19.12\PlatformSpecificUtils.h>
//#include<pcapplusplus19.12\UdpLayer.h>
//#include<pcapplusplus19.12\HttpLayer.h>
//
//using namespace pcpp;
//
//#ifdef _DEBUG 
//#pragma comment(lib,"debug\\pthreadVC2.lib")
//#pragma comment(lib, "debug\\Common++.lib")
//#pragma comment(lib, "debug\\Packet++.lib")
//#pragma comment(lib, "debug\\Pcap++.lib")
//#else
//#pragma comment(lib,"release\\pthreadVC2.lib")
//#pragma comment(lib, "release\\Common++.lib")
//#pragma comment(lib, "release\\Packet++.lib")
//#pragma comment(lib, "release\\Pcap++.lib")
//#endif
//
//#pragma comment(lib,"ws2_32.lib")
#include<httpxx\BufferedMessage.hpp>



void all_http_common_request(std::map<std::string, std::string>& mapresult, const http::BufferedRequest &request);
void all_http_common_response(std::map<std::string, std::string>& mapresult, const http::BufferedResponse &reponse);