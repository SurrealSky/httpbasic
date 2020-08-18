// httpbasic.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include<typedef.h>
#include<httpxx/http.hpp>
//#include<unordered_map>
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
		if (bodylen < 0x5)
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
			if ((pbody[0] == 'G'&&pbody[1] == 'E'&&pbody[2] == 'T'&&pbody[3] == 0x20) ||
				(pbody[0] == 'P'&&pbody[1] == 'O'&&pbody[2] == 'S'&&pbody[3] == 'T'&&pbody[4] == 0x20))
			{
				return true;
			}
		}
		return false;
	}
	unsigned int ActualLen(const char *pbody, const unsigned int bodylen, const bool isClient2Server)
	{
		unsigned int len = bodylen;
		try
		{
			//判断是请求还是应答

			if (isClient2Server)
			{
				http::BufferedRequest request;
				request.feed(pbody, bodylen);

				if (request.method_name() == "GET")
				{
					len = bodylen;
				}
				else if (request.method_name() == "POST")
				{
					if (request.has_header("Content-Length"))
					{
						std::string str_content_len = request.header("Content-Length");
						unsigned int content_len = ::strtoll(str_content_len.c_str(), 0, 10);
						len = bodylen + content_len - request.body().size();
					}
				}
				else
				{
					len = bodylen;
				}
			}else
			{
				http::BufferedResponse response;
				response.feed(pbody, bodylen);
				if (response.has_header("Content-Length"))
				{
					std::string str_content_len = response.header("Content-Length");
					unsigned int content_len = ::strtoll(str_content_len.c_str(), 0, 10);
					len = bodylen + content_len - response.body().size();
				}
			}	
		}
		catch (const std::exception& error)
		{
			return len;
		}
		return len;
	}
	std::map<std::string, std::string> Analysis(const char *pbody, const unsigned int bodylen, const bool isClient2Server)
	{
		std::map<std::string, std::string> mapresult;
	
		try
		{
			if (isClient2Server)
			{
				http::BufferedRequest request;
				int used = 0;
				while (used < bodylen) {
					used += request.feed(pbody + used, bodylen - used);
				}
				mapresult.insert(std::pair<std::string, std::string>("method", request.method_name()));
				std::map<std::string, std::string>::const_iterator itor = request.headers().begin();
				for (; itor != request.headers().end(); itor++)
				{
					mapresult.insert(std::pair<std::string, std::string>(itor->first,itor->second));
				}
				mapresult.insert(std::pair<std::string, std::string>("body", request.body()));
			}
			else
			{
				http::BufferedResponse response;
				int used = 0;
				while (used < bodylen) {
					used += response.feed(pbody + used, bodylen - used);
				}
				mapresult.insert(std::pair<std::string, std::string>("status", SurrealDebugLog::string_format("%d", response.status())));
				std::map<std::string, std::string>::const_iterator itor = response.headers().begin();
				for (; itor != response.headers().end(); itor++)
				{
					mapresult.insert(std::pair<std::string, std::string>(itor->first, itor->second));
				}
				mapresult.insert(std::pair<std::string, std::string>("body", response.body()));
			}
		}
		catch (const std::exception& error)
		{
			mapresult.insert(std::pair<std::string, std::string>("error", "http parse error"));
			return mapresult;
		}
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