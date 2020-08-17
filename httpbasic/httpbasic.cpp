// httpbasic.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include<typedef.h>
#include<httpxx/http.hpp>

#include <iostream>
#include <ctime>


#define MYPORT(port) (port == 80|| port == 8080 || port==443 || port==8000) 

class httpAnalyzer : public IAnalyzer
{
public:
	~httpAnalyzer()
	{
	}
public:
	bool IsClient2Server(const unsigned int srcPort, const unsigned int dstPrt)
	{
		if MYPORT(srcPort)
			return false;
		else if MYPORT(dstPrt)
			return true;
	}
	bool ForFilter(const unsigned int srcPort, const unsigned int dstPrt, const char *pbody, const unsigned int bodylen)
	{
		//长度过滤
		if (bodylen < 0x9)
		{
			return false;
		}
		//在端口过滤
		bool isFilter = false;
		if MYPORT(srcPort)
			isFilter = true;
		if (!isFilter)
		{
			if MYPORT(dstPrt)
				isFilter = true;
		}
		if (isFilter)
		{
			//常规会话流特征判断
			try
			{
				// Parse request in random increments.
				http::BufferedRequest request;
				request.feed(pbody, bodylen);
				if (!request.complete()) {
					std::cerr << "Request still needs data." << std::endl;
					return (EXIT_FAILURE);
				}
				// Show that we've parsed it correctly.
				std::cout
					<< "Connection: '" << request.header("Connection") << "'."
					<< std::endl;
				std::cout
					<< "Host: '" << request.header("Host") << "'."
					<< std::endl;
				std::cout
					<< "Fubar: '" << request.header("Fubar") << "'."
					<< std::endl;
				std::cout
					<< "Body: '" << request.body() << "'."
					<< std::endl;
			}
			catch (const std::exception& error)
			{
				std::cerr
					<< error.what()
					<< std::endl;
				return false;
			}
		}
		return false;
	}
	unsigned int ActualLen(const char *pbody, const unsigned int bodylen, const bool isClient2Server)
	{
		unsigned int len = 0;
		if (pbody[0] == 0x28)
		{
			len = 2;
			unsigned int offset = 1;
			len = len + STswab32(*(int*)(pbody + offset));
			offset += 4;
			len += 4;
			len = len + STswab32(*(int*)(pbody + offset));
			len += 4;
		}
		else if (pbody[0] == 0x5b)
		{
			unsigned int offset = 1;
			len = STswab16(*(short*)(pbody + offset));
		}

		return len;
	}
	std::map<std::string, std::string> Analysis(const char *pbody, const unsigned int bodylen, const bool isClient2Server)
	{
		std::map<std::string, std::string> mapresult;
	
		return mapresult;
	}

	std::map<std::string, std::string> AnalysisList(const std::list<IAnalyzerData>& packets)
	{
		std::map<std::string, std::string> mapresult;

		return mapresult;
	}
};

PLUGIN_FUNC IAnalyzer *CreateAnalyzer()
{
	return new httpAnalyzer;
}

PLUGIN_FUNC void DestroyAnalyzer(IAnalyzer *r)
{
	delete r;
}

PLUGIN_DISPLAY_NAME("HTTP Analyzer");

PLUGIN_INIT()
{
	// register our new renderer
	RegisterAnalyzerer("HTTP Analyzer", CreateAnalyzer, DestroyAnalyzer);
	return 0;
}