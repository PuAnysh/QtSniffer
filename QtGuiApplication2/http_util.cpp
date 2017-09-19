#include "http_util.h"
int min(int x, int y) {
	return x < y ? x : y;
}
 int CHttpResponseMaker::make(const char* szContent, int nContentLen, char* szBuffer, int nBufferSize, const char* szContentType)
{
	//新增了Access-Control-Allow-Origin *\r\n 正式环境需要去掉
	sprintf(szBuffer, "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %d\r\nContent-Type: %s\r\nConnection: Keep-Alive\r\n\r\n",
		nContentLen, szContentType);
	int nHeadLen = strlen(szBuffer);
	if(nContentLen > 0)
	{
		memcpy(szBuffer+nHeadLen, szContent, nContentLen);
		szBuffer[nHeadLen + nContentLen] = 0;
	}
	return strlen(szBuffer);
}

 void CHttpResponseMaker::make_string(const string& strContent, string& strResp, const string& strContentType)
{
	CHttpBuffer buffer(4096+strContent.size());
	make(strContent.c_str(), strContent.size(), buffer.buf, buffer.size, strContentType.c_str());
	strResp = buffer.buf;
}
 void CHttpResponseMaker::make_404_error(string& strResp)
{
	string strContent;
	strContent += "<html>\r\n";
	strContent += "<head><title>404 Not Found</title></head>\r\n";
	strContent += "<body bgcolor=\"white\">\r\n";
	strContent += "<center><h1>404 Not Found</h1></center>\r\n";
	strContent += "<hr><center>http_util</center>\r\n";
	strContent += "</body>\r\n";
	strContent += "</html>\r\n";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";
	strContent += "<!-- The padding to disable MSIE's friendly error page -->";

	char szTemp[100];
	sprintf(szTemp, "Content-Length: %d\r\n", (int)strContent.size());

	strResp = "HTTP/1.1 404 Not Found\r\n";
	strResp += "Server: http_util\r\n";
	strResp += "Content-Type: text/html; charset=UTF-8\r\n";
	strResp += szTemp;
	strResp += "Connection: keep-alive\r\n";
	strResp += "\r\n";
	strResp += strContent;
}
 void CHttpResponseMaker::make_302_error(const string& strLocation, const string& strMoveTo, string& strResp)
{
	string strContent;
	strContent += "<html><head><title>Object moved</title></head><body>\r\n";
	strContent += "<h2>Object moved to <a href=\"";
	strContent += strMoveTo;
	strContent += "\">here</a>.</h2>\r\n";
	strContent += "</body></html>\r\n";

	char szTemp[100];
	sprintf(szTemp, "Content-Length: %d\r\n", (int)strContent.size());

	strResp = "HTTP/1.1 302 Found\r\n";
	strResp += "Server: http_util\r\n";
	strResp += "Content-Type: text/html; charset=UTF-8\r\n";
	strResp += szTemp;
	strResp += "Connection: keep-alive\r\n";
	strResp += "Location: ";
	strResp += strLocation + "\r\n";
	strResp += "\r\n";
	strResp += strContent;
}


 void CHttpParamStringMaker::add_param(const string& strKey, const string& strValue)
{
	Param param;
	param.strKey = strKey;
	param.strValue = strValue;
	m_params.push_back(param);
}
 void CHttpParamStringMaker::add_param(const string& strKey, unsigned int nValue)
{
	char szValue[100];
	sprintf(szValue, "%u", nValue);
	add_param(strKey, szValue);
}
 void CHttpParamStringMaker::add_param(const string& strKey, int nValue)
{
	char szValue[100];
	sprintf(szValue, "%d", nValue);
	add_param(strKey, szValue);
}
 void CHttpParamStringMaker::del_param(const string& strKey)
{
	list<Param>::iterator it;
	for(it = m_params.begin(); it != m_params.end(); it++)
	{
		Param& item = *it;
		if(item.strKey == strKey)
		{
			m_params.erase(it);
			break;
		}
	}
}
 void CHttpParamStringMaker::clear()
{
	m_params.clear();
}
 void CHttpParamStringMaker::set_paramlines(const string& strParamLines)
{
	m_strParamLines = strParamLines;
}
 string CHttpParamStringMaker::get_params()
{
	if(!m_strParamLines.empty())
		return m_strParamLines;

	CHttpBuffer bufParams;
	CHttpBuffer bufKeyValue;
	list<Param>::iterator it;
	for(it = m_params.begin(); it != m_params.end(); it++)
	{
		Param param = *it;

		sprintf(bufKeyValue.buf, "%s=%s&", param.strKey.c_str(), param.strValue.c_str());
		strcat(bufParams.buf, bufKeyValue.buf);
	}
	if(bufParams.buf[strlen(bufParams.buf) -1] == '&')
		bufParams.buf[strlen(bufParams.buf) -1] = 0;

	string strParams = bufParams.buf;
	return strParams;
}


 int CHttpMaker::make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize)
{
	return GET_make(strHost, nPort, strUri, szBuffer, nBufferSize);
}
 void CHttpMaker::make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest)
{
	GET_make_string(strHost, nPort, strUri, strRequest);
}
 int CHttpMaker::GET_make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize)
{
	char szPort[100] = {0};
	if(nPort != 80)
	{
		sprintf(szPort, ":%d", nPort);
	}
	string strParams = get_params();
	sprintf(szBuffer, "GET %s?%s HTTP/1.1\r\nHost: %s%s\r\nConnection: Keep-Alive\r\nAccept: */*\r\nUser-Agent: http_util\r\n\r\n",
		strUri.c_str(), strParams.c_str(), strHost.c_str(), szPort);
	return strlen(szBuffer);
}
 void CHttpMaker::GET_make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest)
{
	CHttpBuffer buf;
	GET_make(strHost, nPort, strUri, buf.buf, buf.size);
	strRequest = buf.buf;
}
 int CHttpMaker::POST_make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize)
{
	char szPort[100] = {0};
	if(nPort != 80)
	{
		sprintf(szPort, ":%d", nPort);
	}
	string strParams = get_params();
	string strContentType = "application/x-www-form-urlencoded; charset=UTF-8";//二进制用application/octet-stream
	sprintf(szBuffer, "POST %s HTTP/1.1\r\nHost: %s%s\r\nContent-type: %s\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n%s",
		strUri.c_str(), strHost.c_str(), szPort, strContentType.c_str(), (int)strParams.size(), strParams.c_str());
	return strlen(szBuffer);
}
 void CHttpMaker::POST_make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest)
{
	CHttpBuffer buf;
	POST_make(strHost, nPort, strUri, buf.buf, buf.size);
	strRequest = buf.buf;
}


 int CHttpLengthAnaly::get_length(const char* szData, int nDataLen)
{
	int nContentPos;
	int nContentLen;
	return get_length_ex(szData, nDataLen, nContentPos, nContentLen);
}
 int CHttpLengthAnaly::get_length_ex(const char* szData, int nDataLen, int& nContentPos, int& nContentLen)
{
	bool isChunked;
	return get_length_ex2(szData, nDataLen, nContentPos, nContentLen, isChunked);
}
 int CHttpLengthAnaly::get_length_ex2(const char* szData, int nDataLen, int& nContentPos, int& nContentLen, bool& isChunked)
{
	bool bGetType = false;
	bool bPostType = false;
	bool bRespType = false;
	isChunked = false;
	if(memcmp(szData, "GET ", 4) == 0)
	{
		bGetType = true;
	}
	else if(memcmp(szData, "POST ", 5) == 0)
	{

		bPostType = true;
	}
	else if(memcmp(szData, "HTTP/", 5) == 0)
	{
		bRespType = true;
	}
	else
	{
		return -1;
	}

	//根据http头结束符判断
	char* pHeadEnd = strstr((char*)szData, "\r\n\r\n"); ///P:请求行+首部  首部结尾空了一行
	if(!pHeadEnd)
		return 0;

	nContentPos = 0;
	nContentLen = 0;
	int nHeadLen = pHeadEnd+4-szData;  ///首部长度(请求行+首，这里根据空行把报文分成两部分首部和主体)
	int nChunkFlagLen = 0;
	if(bPostType || bRespType)
	{
		char* pContentLen = strstr((char*)szData, "Content-Length:");
		if(pContentLen)
		{
			pContentLen += strlen("Content-Length:");//指针位置向后移动
			char* pContentLenEnd = strstr(pContentLen, "\r\n");
			if(pContentLenEnd)
			{
				CHttpBuffer buf(100);
				memset(buf.buf, 0, buf.size);
				memcpy(buf.buf, pContentLen, min(buf.size,(int)(pContentLenEnd-pContentLen))); /////////
				nContentLen = atoi(buf.buf);///////nContentLen 主体部分长度

				//内容的相对位置
				nContentPos = pHeadEnd-szData + strlen("\r\n\r\n");
			}
		}
		//else
		//{   ////Transfer-Encoding: chunked")这个地方还有问题暂时 屏蔽
		//	isChunked = strstr((char*)szData, "Transfer-Encoding: chunked") ? true : false;     ///////////////////数据包Content-Length是未知的。
		//	if(isChunked)
		//	{
		//		char* szLen = pHeadEnd+ strlen("\r\n\r\n");
		//		char* szChunk = strstr(szLen, "\r\n");
		//		if(szChunk)
		//		{
		//			szChunk += strlen("\r\n");
		//			CHttpBuffer buf(100);
		//			memset(buf.buf, 0, buf.size);
		//			int nLen = szChunk-szLen-strlen("\r\n");    ////////////len首部长度
		//			memcpy(buf.buf, szLen, min(buf.size, nLen));
		//			sscanf(buf.buf,"%x",&nContentLen);//将buf.buf的值赋给nContentLen
		//			nChunkFlagLen = szChunk-szLen;
		//		}
		//	}
		//}
	}

	int nTotalHttpProtocolLen = nHeadLen + nContentLen + nChunkFlagLen;
	if(nDataLen < nTotalHttpProtocolLen)
		return 0;

	return nTotalHttpProtocolLen;
}


 bool CHttpParamParser::parse(const string& strHttpParam)
{
	return parse(strHttpParam.c_str(), strHttpParam.size());
}

 bool CHttpParamParser::parse(const char* szHttpParam, int nLen)
{
	//清理内存
	m_mapValues.clear();

	//复制到缓冲
	CHttpBuffer buf(4096+nLen);
	//fix crash
	//有时候前端上传的参数是 &aa=1 这种，前面多个&
	if(szHttpParam[0] == '&')
		memcpy(buf.buf, szHttpParam + 1, nLen-1);
	else
		memcpy(buf.buf, szHttpParam, nLen);
	buf.buf[nLen] = 0;
	if(buf.buf[strlen(buf.buf)-1] != '&')
		strcat(buf.buf, "&");

	CHttpBuffer bufKeyValue(4096+nLen);

	//处理参数
	char* szParam = buf.buf;
	while(1)
	{
		if(szParam[0] == '\0')
			break;

		// 		if(!check_ansi(szParam[0]))
		// 			break;
		// 
		// 		if(szParam[0] != '=' && szParam[0] != '&')
		// 		{
		// 			szParam ++;
		// 			continue;
		// 		}

		if(!((szParam[0] >='a' && szParam[0] <='z') || (szParam[0] >='A' && szParam[0] <='Z') || szParam[0]=='%' || szParam[0]=='+' || szParam[0]=='_'))
		{
			szParam ++;
			continue;
		}

		char* szValue = strchr(szParam, '=');
		if(!szValue)
			break;

		char* szSplit = strchr(szParam, '&');
		if(!szSplit)
			break;

		//2014-5-30 fix
		//安全检查：边界不能越界
		if(szSplit < szValue)
		{
			//RT_ERROR_TRACE("CHttpParser::parse range check failed!");
			break;
		}

		string strKey;
		string strValue;

		//2014-5-30 fix
		//安全检查：key和value必须有效，且不大于4k长度
		int nKeyLen = szValue-szParam;
		int nValueLen = szSplit-szValue-1;
		if(nKeyLen < 0 || nKeyLen > 4096)
		{
			//RT_ERROR_TRACE("CHttpParser::parse nKeyLen check failed! nKeyLen:"<<nKeyLen);
			break;
		}
		//if(nValueLen < 0 || nValueLen > 4024)
		//2015-2-6 修改，由于ios支付的参数有7k，所以这里将上限改为32k
		if(nValueLen < 0 || nValueLen > 32*1024)
		{
			//RT_ERROR_TRACE("CHttpParser::parse nValueLen check failed! nValueLen:"<<nValueLen);
			break;
		}

		//提取key
		memset(bufKeyValue.buf, 0, bufKeyValue.size);
		memcpy(bufKeyValue.buf, szParam, nKeyLen);
		strKey = bufKeyValue.buf;

		//提取value
		memset(bufKeyValue.buf, 0, bufKeyValue.size);
		memcpy(bufKeyValue.buf, szValue+1, nValueLen);
		strValue = bufKeyValue.buf;

		//保存
		m_mapValues.insert(std::make_pair(strKey, strValue));
		//printf("parse http request, key:%s, value:%s \r\n", strKey.c_str(), strValue.c_str());

		//下一个参数
		szParam = szSplit + 1;
	}

	return true;
}

 string CHttpParamParser::get_param(const char* szKey)
{
	map<string, string>::iterator it = m_mapValues.find(szKey);
	if(it != m_mapValues.end())
	{
		return it->second;
	}
	else
	{
		return "";
	}
}
 int CHttpParamParser::get_param_int(const char* szKey)
{
	return atoi(get_param(szKey).c_str());
}
 string CHttpParamParser::get_sort_param_string()
{
	string strSort;
	map<string, string>::iterator it;
	for(it = m_mapValues.begin(); it != m_mapValues.end(); it++)
	{
		if(!strSort.empty())
			strSort += "&";

		strSort += it->first;
		strSort += "=";
		strSort += it->second;
	}
	return strSort;
}

 int CHttpParser::parse(const char* szHttpReq, int nDataLen, int nExtraParamType)/////包，报文长度，
// int CHttpParser::parse(const char* szHttpReq, int nDataLen, int nExtraParamType)
{
	int nContentPos = 0;

	if(!check_security(szHttpReq))
		return -1;

	m_nExtraParamType = nExtraParamType;

	//判断是否接收完成
	bool isChunked = false;
	int nTotalLen = CHttpLengthAnaly::get_length_ex2(szHttpReq, nDataLen, nContentPos, m_nContentLen, isChunked); //////////////包，报文长度，
	if(nTotalLen <= 0)
		return nTotalLen;
	
	//分离头域字段
	if(!parseField(szHttpReq, nTotalLen))  
		return -1;

	//分析第一行的信息
	if(!parseFirstLine())
		return -1;

	//对chunk方式调整
	if(isChunked)
	{
#ifdef __x86_64__
		char* pTmp = (char*)strstr(m_pszContent, "\r\n");
#else
		char* pTmp = (char*)strstr(m_pszContent, "\r\n");
#endif
		if(pTmp)
		{
			m_pszContent = pTmp + strlen("\r\n");
		}
	}

	//分析参数详细信息
	if(m_pszActParam)   ///问号后面跟的参数
	{
		if(nExtraParamType == HTTP_UTIL_PARAM_ALL || nExtraParamType == HTTP_UTIL_PARAM_HEADPARAM)
		{
			m_paramParser.parse(m_pszActParam, strlen(m_pszActParam));
		}
	}
	else if(m_pszContent)
	{
		if(nExtraParamType == HTTP_UTIL_PARAM_ALL || nExtraParamType == HTTP_UTIL_PARAM_CONTENT)
		{
			m_paramParser.parse(m_pszContent, m_nContentLen);
		}
	}

	return nTotalLen;
}

 bool CHttpParser::parseField(const char* szHttpReq, int nTotalLen)
{
	//获取第一行
	char* ptr = strstr((char*)szHttpReq, "\r\n");
	if(!ptr)
		return false;
	
	CInsertTempZero z1(ptr);
	strncpy(m_bufFirstLine.buf, szHttpReq, m_bufFirstLine.size-1);  ///// 报文首部内容都放到m_bufFirstLine.buf
	ptr += strlen("\r\n");  ///ptr指向报文主体
	
	while(1)
	{
		//防止越界
		if(ptr > szHttpReq + nTotalLen - 4)	//4 == strlen("\r\n\r\n")
			break;

		//是否到了文本区域末尾
		if(memcmp(ptr, "\r\n", 2) == 0)
			break;

		//行末
		char* pLineEnd = strstr(ptr, "\r\n");
		if(!pLineEnd)
			break;

		CInsertTempZero zLineEnd(pLineEnd);
		
		//对一行进行分析
		char* p = strstr(ptr, ": ");
		if(!p)
		{
			break;
		}

		//提取头域名和值
		CInsertTempZero zp(p);
		string strFieldName = ptr;

		p += strlen(": ");
		string strValue = p;
		
		m_mapFields.insert(std::make_pair(strFieldName, strValue));  
		
		if (strFieldName=="Host")
		{
			string tempstr=strValue;
			string tempstr1=strValue;
		}



		ptr = pLineEnd + strlen("\r\n");
	}

	ptr += strlen("\r\n");

	if(ptr < szHttpReq + nTotalLen)
	{
		m_pszContent = ptr;
	}
	return true;
}

 bool CHttpParser::parseFirstLine()
{
	if(strlen(m_bufFirstLine.buf) < 10)		//第一行不能小于10个字符
		return false;

	char* pBegin = NULL;
	//分析method
	if(parseMethod(m_bufFirstLine.buf, "GET ", HTTP_UTIL_METHOD_GET))
	{
		pBegin = m_bufFirstLine.buf + 4;
	}
	else if(parseMethod(m_bufFirstLine.buf, "POST ", HTTP_UTIL_METHOD_POST))
	{
		pBegin = m_bufFirstLine.buf + 5;
	}
	else if(parseMethod(m_bufFirstLine.buf, "HTTP/", HTTP_UTIL_METHOD_RESP))
	{
		pBegin = m_bufFirstLine.buf + 5;
	}
	
	//没找到可支持的method则返回
	if(m_nHttpMethod == HTTP_UTIL_METHOD_NONE)
		return false;

	//提取uri和动作参数
	char* szParam = strchr(pBegin, '?');
	if(szParam)
	{
		*szParam = 0;
		m_pszActParam = szParam+1; 
	}
	m_pszUri = pBegin;
	return true;
}
 bool CHttpParser::parseMethod(const char* szFirstLine, const char* szMethod, int nMethodType)  ///if(parseMethod(m_bufFirstLine.buf, "GET ", HTTP_UTIL_METHOD_GET))
{
	int len = strlen(szMethod);
	if(memcmp(m_bufFirstLine.buf, szMethod, len) == 0)
	{
		char* pEnd = strstr(m_bufFirstLine.buf, " HTTP");
		if(!pEnd)
		{
			pEnd = strstr(m_bufFirstLine.buf, " OK");
		}
		if(pEnd)
		{
			*pEnd = 0;
			m_nHttpMethod = nMethodType;
			return true;
		}
	}
	return false;
}


 string CHttpParser::get_head_field(const string& strFieldName)
{
	map<string, string>::iterator it = m_mapFields.find(strFieldName);
	if(it != m_mapFields.end())
	{
		return it->second;
	}
	return "";
}
 string CHttpParser::ContentType()
{
	return get_head_field("Content-Type");
}

 string CHttpParser::get_host()
{
	return get_head_field("Host");
}
 string CHttpParser::get_cookie()
{
	return get_head_field("Cookie");
}

 string CHttpParser::get_param(const char* szKey)
{
	return m_paramParser.get_param(szKey);
}
 int CHttpParser::get_param_int(const char* szKey)
{
	return m_paramParser.get_param_int(szKey);
}

 string CHttpParser::get_param_string()
{
	if(m_pszActParam && (m_nExtraParamType == HTTP_UTIL_PARAM_ALL || m_nExtraParamType == HTTP_UTIL_PARAM_HEADPARAM))
		return m_pszActParam;

	if(m_pszContent && (m_nExtraParamType == HTTP_UTIL_PARAM_ALL || m_nExtraParamType == HTTP_UTIL_PARAM_CONTENT))
		return m_pszContent;

	return "";
}

 string CHttpParser::get_uri()
{
	if(!m_pszUri)
		return "";

	return m_pszUri;
}
 string CHttpParser::get_object()
{
	if(!m_pszUri)
		return "";
	
	char* ptr = strrchr((char*)m_pszUri, '/');
	if(!ptr)
		return "";

	return ptr+1;
}

 int CHttpParser::get_http_method()
{
	return m_nHttpMethod;
}
 string CHttpParser::get_sort_param_string()
{
	return m_paramParser.get_sort_param_string();
}

 bool CHttpParser::check_security(const char* szHttpReq)
{
	//有些人会进行攻击，如内容填写为 &('\043_memberAccess[\'allowStaticMethodAccess\']')(meh)=true&(aaa)(('\043context[\'xwork.MethodAccessor.denyMethodExecution\']\075\043foo')('\043foo\075false'))&(asdf)(('@org.apache.struts2.ServletActionContext@getResponse().addHeader("XYZXYZ"\054"XYZXYZ")')(a))=1
	if(strchr(szHttpReq, '\'') != NULL)
	{
		//RT_ERROR_TRACE("CHttpParser::check_security failed!");
		return false;
	}

	/*
	//2014-5-30 fix
	//只要出现不可见的字符，就认为有问题，可见字符范围是[32,126]
	int nHttpRequestLen = strlen(szHttpReq);
	for(int i=0; i<nHttpRequestLen; i++)
	{
		if(!check_ansi(szHttpReq[i]))
		{
			RT_ERROR_TRACE("CHttpParser::check_security failed! exist not ansi char");
			return false;
		}
	}
	*/
	return true;
}

 char* CHttpParser::get_content()
{
	return m_pszContent;
}

/////////////////////////////////////////////////////////////////////////////

