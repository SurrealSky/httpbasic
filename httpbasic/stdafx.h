// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ���ų�����ʹ�õ�����
// Windows ͷ�ļ�: 
#include <windows.h>



// TODO:  �ڴ˴����ó�����Ҫ������ͷ�ļ�
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