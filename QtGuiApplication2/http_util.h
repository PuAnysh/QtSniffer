/********************************************************************
	
	����httpЭ����
*********************************************************************/

#pragma once

#include <assert.h>
#include <string>
#include <map>
#include <list>
#include <iterator>
using namespace std;

#define HTTPUTIL_BUFFER_SIZE		32*1024

//���Գ���
/*
	void test()
	{
		char sz[1024];
		memset(sz, 0, sizeof(sz));
		FILE* fp = fopen("e:\\HTTP_UTIL_resp.txt", "rb");
		int len = fread(sz, 1, 1024, fp);
		fclose(fp);

		//���Խ���
		CHttpParser parser(sz, len);
		string strJsSessionID = parser.get_param("name");
		
		//���Դ��
		CHttpResponseMaker make;
		string strContent = "ok";
		string strResp;
		make.make_string(strContent, strResp);
	}
*/

enum HttpMethodType{
	HTTP_UTIL_METHOD_NONE,
	HTTP_UTIL_METHOD_GET,
	HTTP_UTIL_METHOD_POST,
	HTTP_UTIL_METHOD_RESP
};


enum HttpParamType{
	HTTP_UTIL_PARAM_ALL,			//�������͵Ĳ���
	HTTP_UTIL_PARAM_HEADPARAM,		//ֻ��ȡHEADPARAM
	HTTP_UTIL_PARAM_CONTENT			//ֻ��ȡCONTENT
};

class CHttpBuffer
{
public:
	CHttpBuffer(int nMaxLen = HTTPUTIL_BUFFER_SIZE)
	{
		buf = new char[nMaxLen];
		size = nMaxLen;
		buf[0] = 0;
	}
	virtual ~CHttpBuffer()
	{
		if(buf)
		{
			delete []buf;
			buf = NULL;
		}
		size = 0;
	}
public:
	char*	buf;
	int		size;
};

static bool check_ansi(char c)
{
	if(c != '\x0A' && c != '\x0D' && (c < 32 || c > 126))
	{
		return false;
	}
	return true;
}

/////////////////////////////////////////////////////////////////////////////
//����http��Ӧ��
#define HTTP_CONTENT_TYPE_TXT	"text/html;charset=utf-8"
#define HTTP_CONTENT_TYPE_JSON	"application/json;charset=utf-8"
#define HTTP_CONTENT_TYPE_XML	"text/xml;charset=utf-8"
#define HTTP_CONTENT_TYPE_WWW	"application/x-www-form-urlencoded"

class CHttpResponseMaker
{
public:
	CHttpResponseMaker(){}
	virtual ~CHttpResponseMaker(){}
public:
	static int		make(const char* szContent, int nContentLen, char* szBuffer, int nBufferSize, const char* szContentType=HTTP_CONTENT_TYPE_JSON);
	static void		make_string(const string& strContent, string& strResp, const string& strContentType=HTTP_CONTENT_TYPE_JSON);
	static void		make_404_error(string& strResp);
	static void		make_302_error(const string& strLocation, const string& strMoveTo, string& strResp);
protected:
private:
};



/////////////////////////////////////////////////////////////////////////////
//��������ַ���
class CHttpParamStringMaker
{
public:
	CHttpParamStringMaker(){}
	virtual ~CHttpParamStringMaker(){}
	typedef struct 
	{
		string strKey;
		string strValue;
	}Param;

public:
	void	add_param(const string& strKey, const string& strValue);
	void	add_param(const string& strKey, unsigned int nValue);
	void	add_param(const string& strKey, int nValue);
	void	del_param(const string& strKey);
	void	clear();
	void	set_paramlines(const string& strLines);
	string  get_params();
public:
	list<Param>	m_params;
	string m_strParamLines;
};


/////////////////////////////////////////////////////////////////////////////
//���������
class CHttpMaker	: public CHttpParamStringMaker
{
public:
	CHttpMaker(){}
	virtual ~CHttpMaker(){}

public:
	int		make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize);
	void	make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest);

public:
	int		GET_make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize);
	void	GET_make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest);

	int		POST_make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize);
	void	POST_make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest);
};


/////////////////////////////////////////////////////////////////////////////
//����GET�����
class CHttpGetMaker	: public CHttpMaker
{
public:
	CHttpGetMaker(){}
	virtual ~CHttpGetMaker(){}

public:
	int make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize)
	{
		return GET_make(strHost, nPort, strUri, szBuffer, nBufferSize);
	}
	void make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest)
	{
		GET_make_string(strHost, nPort, strUri, strRequest);
	}
};

/////////////////////////////////////////////////////////////////////////////
//����POST�����
class CHttpPostMaker	: public CHttpMaker
{
public:
	CHttpPostMaker(){}
	virtual ~CHttpPostMaker(){}
	
public:
	int make(const string& strHost, unsigned short nPort, const string& strUri, char* szBuffer, int nBufferSize)
	{
		return POST_make(strHost, nPort, strUri, szBuffer, nBufferSize);
	}
	void make_string(const string& strHost, unsigned short nPort, const string& strUri, string& strRequest)
	{
		POST_make_string(strHost, nPort, strUri, strRequest);
	}
};

/////////////////////////////////////////////////////////////////////////////
//����Http�����ݰ����ȣ�֧��GET\POST\RESP
class CHttpLengthAnaly
{
public:
	CHttpLengthAnaly(){}
	virtual ~CHttpLengthAnaly(){}
public:
	//��ȡ���ȣ��������ݷ���-1�����ݲ���������0��������ȫ����>0
	static int		get_length(const char* szData, int nDataLen);

	//��ȡ���ȣ��������ݷ���-1�����ݲ���������0��������ȫ����>0
	//nContentPos�������������λ��
	static int		get_length_ex(const char* szData, int nDataLen, int& nContentPos, int& nContentLen);

	//��ȡ���ȣ��������ݷ���-1�����ݲ���������0��������ȫ����>0
	//nContentPos�������������λ��
	static int		get_length_ex2(const char* szData, int nDataLen, int& nContentPos, int& nContentLen, bool& isChunked);
};


/////////////////////////////////////////////////////////////////////////////
//��������
//˵�������ڽ�����aaa=123&bbb=321&ccc=888֮����ַ���
class CHttpParamParser
{
public:
	CHttpParamParser(const char* szHttpParam = NULL, int nLen = 0)
	{
		if(szHttpParam && nLen > 0)
		{
			parse(szHttpParam, nLen);
		}
	}
	virtual ~CHttpParamParser(){}

public:
	bool parse(const char* szHttpParam, int nLen);
	bool parse(const string& strHttpParam);
	string get_param(const char* szKey);
	int get_param_int(const char* szKey);
	//��ȡ��key������Ĳ����ַ���
	string get_sort_param_string();

private:
	map<string, string> m_mapValues;
};



/////////////////////////////////////////////////////////////////////////////
//�����ַ�������
class CInsertTempZero
{
public:
	CInsertTempZero(char* pSrc)
	{
		m_szOld = *pSrc;
		m_pSrc = pSrc;
		*m_pSrc = 0;
	}
	virtual ~CInsertTempZero()
	{
		*m_pSrc = m_szOld;
	}
protected:
private:
	char* m_pSrc;
	char  m_szOld;
};

/////////////////////////////////////////////////////////////////////////////
//HTTPЭ�������
class CHttpParser
{
public:
	CHttpParser(const char* szHttpReq = NULL, int nDataLen = 0, int nExtraParamType = HTTP_UTIL_PARAM_ALL)
		: m_pszContent(NULL)
		, m_nContentLen(0)
		, m_nHttpMethod(HTTP_UTIL_METHOD_NONE)
		, m_pszUri(NULL)
		, m_pszActParam(NULL)
		, m_nExtraParamType(HTTP_UTIL_PARAM_ALL)
	{
		if(szHttpReq != NULL)
		{
			if(nDataLen > 0)
			{
				parse(szHttpReq, nDataLen, nExtraParamType);
			}
			else
			{
				assert(0);
			}
		}
	}

	virtual ~CHttpParser(){}

public:
	//�������ݷ���-1�����ݲ���������0��������ȫ����>0
	int parse(const char* szHttpReq, int nDataLen, int nExtraParamType = HTTP_UTIL_PARAM_ALL);

		//��ȡ����ͷ�����ֵ
	string get_head_field(const string& strFieldName);

	//��ȡ��������
	string get_host();

	//��ȡcontent_type��
	inline string CHttpParser::ContentType();

	//��ȡcookie
	string get_cookie();

	//��ȡ���������ֵ
	string get_param(const char* szKey);
	int get_param_int(const char* szKey);

	//��ȡ�����ַ������� "aaa=123&bbb=321&ccc=888"
	string		get_param_string();
	
	//��ȡuri���ݣ��� "/update/mytest"
	string		get_uri();

	//��ȡobject������http://127/aa/bb/cc?fff=999 �е�cc
	string		get_object();
	
	//��ȡ����
	int			get_http_method();

	//��ȡ��key������Ĳ����ַ���
	string		get_sort_param_string();

	char *      get_content();

protected:
	//����ͷ��
	bool parseField(const char* szHttpReq, int nTotalLen);
	//������һ�У���ȡmethod��headparam
	bool parseFirstLine();
	//����method
	bool parseMethod(const char* szFirstLine, const char* szMethod, int nMethodType);

	//��ȫУ��
	bool check_security(const char* szHttpReq);

private:
	map<string, string>	m_mapFields;
	CHttpBuffer			m_bufFirstLine;
    char*			m_pszContent;
	int					m_nContentLen;
	int					m_nHttpMethod;
	
	const char*			m_pszUri;
	const char*			m_pszActParam;

	CHttpParamParser	m_paramParser;		//����������

	int					m_nExtraParamType;
};

