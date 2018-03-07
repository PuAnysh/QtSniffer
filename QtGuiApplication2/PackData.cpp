#include "PackData.h"



PackData::PackData()
{
}

PackData::PackData(const u_char * str , int len)
{
	date = new u_char[len];
	memcpy(date, str, len);
}


PackData::~PackData()
{
	delete[] date;
}
