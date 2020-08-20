// stdafx.cpp : 只包括标准包含文件的源文件
// httpbasic.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"
#include"wx_stackreport.h"

// TODO: 在 STDAFX.H 中引用任何所需的附加头文件，
//而不是在此文件中引用

void all_http_common_request(std::map<std::string, std::string>& mapresult, const pcpp::HttpRequestLayer &httplayer)
{
	wx_stackreport_complete(mapresult, httplayer);
}

void all_http_common_response(std::map<std::string, std::string>& mapresult, const pcpp::HttpResponseLayer &httplayer)
{

}