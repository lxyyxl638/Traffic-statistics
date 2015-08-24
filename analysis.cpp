/******************************************************************************
 * 文件名称： analysis.cpp
 * 文件描述： 服务器流量统计
 * 创建日期： 2015/8/22
 * 文件版本： v1.0
 * 作    者：carsonlin(林小阳)
 * 函数列表： Handler AddLog
 * Copyright 1998 - 2008 TENCENT Inc. All Rights Reserved
 * 修改历史：
        <作者>        <修改日期>          <修改描述>
 ******************************************************************************/

#include <cstdlib>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <map>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h> 
#include <arpa/inet.h>
#include <errno.h>
#include "CUnifiedStorageProtocolNetV2.h"
#include <cassert>
#include <string>
#include <wait.h>
// 注意此处，勿漏:
using namespace SEC;
using namespace std;
CUnifiedStorageProtocolNetV2 g_proto;

// IP 54.228.183.9.443 > 10.70.102.92.49725: tcp 197
// 	IP 10.70.102.92.55535 > 10.1.30.40.53: UDP, length 58
map<string,uint64_t> g_UdpMap;

unsigned int uiTimes = 0;
unsigned int uiTimesLimit = 0;
const unsigned int LENGTH = 1024;
const uint16_t SYSID = 890;
uint64_t total_count = 0;
int iFd = 0;

#define htonll ntohll

#pragma pack(1)
struct StLog {
    uint32_t uiSrcIp;
    uint16_t usSrcPort;
    uint32_t uiDestIp;
    uint16_t usDestPort;
    uint64_t ulTime;
    uint64_t ulCount;
};

inline uint64_t ntohll(const uint64_t &ullIn)
{                                                   
    if (1 != ntohs(1))  
    {
        //针对x86
        union 
        {
            uint64_t ddwVal;
            uint32_t adwVal[2];
        }uSrc, uDst;
        uSrc.ddwVal     = ullIn;
        uDst.adwVal[0]  = htonl(uSrc.adwVal[1]);
        uDst.adwVal[1]  = htonl(uSrc.adwVal[0]);
        
        return uDst.ddwVal;     
    } 
    else    
    {
        return ullIn;         
    }
}

void Hton(StLog *pst)
{
    //pst->uiSrcIp = htonl(pst->uiSrcIp);
    pst->usSrcPort = htons(pst->usSrcPort);
    //pst->uiDestIp = htonl(pst->uiDestIp);
    pst->usDestPort = htons(pst->usDestPort);
    pst->ulTime = htonll(pst->ulTime);
    pst->ulCount = htonll(pst->ulCount);
    
}

#pragma pack()

/******************************************************************************
 * 函数名称：AddLog
 * 函数描述: 输出错误日志
 * 输入参数：错误信息
 * 输出参数: 无
 * 返回值  : void
 * 创建日期: 2015/8/22
 * 作    者：carsonlin(林小阳)
 * 修改历史: 
 ******************************************************************************/
/*
void AddLog(const char * pszErrorStr) 
{
    if (-1 == write(iFd,pszErrorStr,strlen(pszErrorStr) + 1)) 
    {
        perror("Can't write log file");
    }
    return;
}
*/
bool split(string C_str,uint32_t &uiIp,uint16_t &usPort) 
{
	
	  const char * pszStr = (C_str.substr(0,C_str.rfind('.'))).c_str();
    usPort = atoi((C_str.substr(C_str.rfind('.') + 1)).c_str());

	  struct in_addr addrptr;
	  if (0 == inet_aton(pszStr,&addrptr)) 
    {
	      //AddLog("Can't convert the Ip address\n");
        return false;
    } 
    else 
    {
        uiIp = addrptr.s_addr;
        //printf("%u\n",uiIp);
    }
    return true;
}

void SigChld(int iSigno) 
{
    pid_t pid;
    int iStat;

    pid = wait(&iStat);
    //printf("child %d terminated successfully\n",pid);

    return;
}

void handler() 
{
    map<string,uint64_t>::iterator C_it;
    StLog stLog;

    for (C_it = g_UdpMap.begin();C_it != g_UdpMap.end();++C_it) 
    {
        string C_tmp = C_it->first;
        string C_src = C_tmp.substr(0,C_tmp.find('-'));
        string C_dest = C_tmp.substr(C_tmp.find('-') + 1);
        //printf("%s -> %s\n",C_src.c_str(),C_dest.c_str());
        if (split(C_src,stLog.uiSrcIp,stLog.usSrcPort) && split(C_dest,stLog.uiDestIp,stLog.usDestPort)) 
        {
            stLog.ulTime = (uint64_t) time(NULL);
            stLog.ulCount = C_it->second;
            Hton(&stLog);
            uint32_t ulRet = g_proto.SendStruct(&stLog, sizeof(stLog), SYSID, 0, 0);
            if (0 != ulRet) 
            {
                //printf("SendStrcut Fail: ret=%u", ulRet);    // 错误码含义见:CUnifiedStorageProtocolBase.h emUnifiedStorageProtocolReturnCode
            } 
            else 
            {
                //printf("Send successfully\n");
            }
            //printf("%u %u %u %u\n",stLog.uiSrcIp,stLog.usSrcPort,stLog.uiDestIp,stLog.usDestPort);
        } 
        else 
        {
            //AddLog("split string error\n");
        }
    }
    return;
}

int main(int argv, char ** argc) 
{
  if (argv != 2 || atoi(argc[1]) <= 0) 
  {
     printf("%s\n","usage: error of parameter\n" );
     exit(0);
  } 
  else 
  {
     uiTimesLimit = atoi(argc[1]);
  }

  char* pszIpProto = NULL;
  char* pszSrc = NULL;
  char* pszDest = NULL;
  char* pszProto = NULL;
  char* pszBuffer = NULL;
  char* pszTmp = NULL;
  pid_t pid = 0;

  iFd = open("./anal_err_log", O_APPEND|O_WRONLY|O_CREAT,0644);

  if (-1 == iFd) 
  {
      perror("Can't open file");
      if (-1 == system("sh kill_tcpdump.sh")) 
      {
          perror("Can't kill tcpdump, please do it by yourself");
      }
      exit(1);
  }

  pszBuffer = new char[LENGTH];
  
  signal(SIGCHLD,SigChld);
  
  while (fgets(pszBuffer,LENGTH,stdin)) {
      ++uiTimes;

	    pszIpProto = strtok(pszBuffer," ");
	    if (strcmp(pszIpProto,"IP")) {
		      continue;
	    } 
      else 
      {
		      pszSrc = strtok(NULL," ");
		      pszTmp = strtok(NULL," ");
		      pszDest = strtok(NULL,":");
		      pszProto = strtok(NULL,", ");
	    }
	  
	    string strSrc(pszSrc);
	    string strDest(pszDest);
	    string strKey = strSrc + '-' + strDest;
	    ++g_UdpMap[strKey];
      //total_count++;
      //if(total_count%1000 == 0)
      //    printf("total packet of udp:%llu\n",total_count);

      if (uiTimes > uiTimesLimit) 
      {
          if ((pid = fork()) < 0) 
          {
              //AddLog("Can't fork children process\n");
          } 
          else if (pid == 0) 
          {
              handler();
              g_proto.Flush();       
              exit(0);
          } 
          else 
          {
              g_UdpMap.clear();
              uiTimes = 0;
          }
      }
  }
  close(iFd);
  return 0;
}
