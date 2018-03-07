#pragma once
typedef unsigned char   u_char;
#include <cstring>
class PackData
{
public:
	PackData();
	PackData(const u_char* str , int len);
	~PackData();
	u_char * date;
};

