// stdafx.cpp : ֻ������׼�����ļ���Դ�ļ�
// httpbasic.pch ����ΪԤ����ͷ
// stdafx.obj ������Ԥ����������Ϣ

#include "stdafx.h"
#include"wx_stackreport.h"

// TODO: �� STDAFX.H �������κ�����ĸ���ͷ�ļ���
//�������ڴ��ļ�������

void all_http_common_request(std::map<std::string, std::string>& mapresult, const pcpp::HttpRequestLayer &httplayer)
{
	wx_stackreport_complete(mapresult, httplayer);
}

void all_http_common_response(std::map<std::string, std::string>& mapresult, const pcpp::HttpResponseLayer &httplayer)
{

}