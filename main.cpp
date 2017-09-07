#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#define INIT_SOCKET() {WSADATA wsadata;WSAStartup(MAKEWORD(2,2),&wsadata);}
#define CLOSESOCKET(x) closesocket(x)
#define CLEAN_SOCKET() {WSACleanup();}
// http.c 实现http 代理功能
#define PROTO_EXCHANGE_TIMEOUT 15
#define PROTO_RECVRESP_TIMEOUT 75
#define PROTO_SENDRESP_TIMEOUT 10

#define WAIT_AND_RECV(sd,buf,len,waittime,recvflags) \
	do{\
		struct fd_set sset;\
		struct timeval waited;\
		waited.tv_sec = waittime;waited.tv_usec = 0;\
		FD_ZERO(&sset);FD_SET(sd,&sset);\
		if(select(sd+1,&sset,NULL,NULL,&waited) != 1 || (len = recv(sd,buf,len,recvflags))
				== -1 )\
			len = -1;\
	}while(0);
#define DEBUG_DUMP printf
static int httpproxy_connect(
		const char*proxyaddr,
		int proxyport,
	       	const char*dstaddr,
		int dstport)
{
	int proxysd = -1;
	char buf[2048];
	int len;
	char *ptoken;
	int status;
	struct sockaddr_in inaddr;
	if( !proxyaddr || !proxyaddr[0] || proxyport < 1
			||!dstaddr || !dstaddr[0] )
		return -1;
	DEBUG_DUMP(" 代理:%s:%d, 目
			标:%s:%d\n",proxyaddr,proxyport,dstaddr,dstport);
	len = sizeof(inaddr);
	memset(&inaddr,0,len);
	if( (inaddr.sin_addr.s_addr = inet_addr(proxyaddr) ) == INADDR_NONE )
		return -1;
	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(proxyport);
	// connect to proxy
	if((proxysd = socket(AF_INET,SOCK_STREAM,0)) == -1 )
		return -1;
	if( connect(proxysd,(struct sockaddr*)&inaddr,len))
		goto errorparse;
	// 发送connect 请求并判断返回,根据HTTP 协议说明,详细内容请看RFC2616
	// HTTP 代理使用CONNECT 指令实现􀂴CONNECT 时指定选端的地址与端口号,
	// 当代理服务器返回成功后(状态值是2xx),后面的代理服务器不再对此连接的数据
	// 进行HTTP 协议处理
	if( dstport > 0 )
		len = sprintf(buf,"CONNECT %s:%d HTTP/1.1\r\n\r\n",dstaddr,dstport);
	else
		len = sprintf(buf,"CONNECT %s HTTP/1.1\r\n\r\n",dstaddr);
	if( send(proxysd,buf,len,0) != len ){
		DEBUG_DUMP("发送CONNECT 请求失败:包内容:%s\n",buf);
		goto errorparse;
	}
	len = sizeof(buf)-1;
	WAIT_AND_RECV(proxysd,buf,len,PROTO_RECVRESP_TIMEOUT,MSG_PE
			EK);
	if( len == -1){
		DEBUG_DUMP("接收CONNECT 响应失败\n");
		goto errorparse;
	}
	buf[len] = 0;
	DEBUG_DUMP("CONNECT 响应为:%s|\n",buf);
	if( strnicmp(buf,"HTTP/1.",7)
			|| (!strstr(buf,"\r\n\r\n") && !strstr(buf,"\n\n")))
		goto errorparse;
	ptoken = buf;
	while(!isspace(*ptoken) && *ptoken) ptoken ++;
	status = atoi(ptoken);
	if( status < 300 && status > 199 ){
		ptoken = strstr(buf,"\r\n\r\n");
		if( ptoken )
			len = ptoken - buf +4;
		else{
			ptoken = strstr(buf,"\n\n");
			len = ptoken - buf +2;
		}
		WAIT_AND_RECV(proxysd,buf,len,PROTO_RECVRESP_TIMEOUT,0);
		return proxysd;
	}
errorparse:
	CLOSESOCKET(proxysd);
	return -1;
}
// sd [in] 使用socks5 的客户端的连接id
// proxyaddr [in] http 代理地址
// proxyport [in] http 代理端口
// return:
// -1 失败
// >=0 与http 代理的连接id
static int socks5_accept(int sd,const char *proxyaddr,int proxyport)
{
	unsigned char buf[512];
	int len = 2;
	int i = 0;
	char dstaddr[260];
	int dstport;
	if( !proxyaddr || !proxyaddr[0] || proxyport <1 )
		return -1;
	// 处理协商,现在只处理无认证情况,无论对方会不会处理这种情况
	// 没有要求无认证方式,sorry,那我就不理它
	// 另外只处理SOCKS5 的CONNECT 命令,其它不处理
	WAIT_AND_RECV(sd,(char*)buf,len,PROTO_EXCHANGE_TIMEOUT,0);
	if( len != 2 || buf[0] != 5 )
	{
		DEBUG_DUMP("接收socks5 协商包失败,len:%d,buf[0]:%d\n",len,buf[0]);
		return -1;
	}
	len = buf[1];
	i = len;
	WAIT_AND_RECV(sd,(char*)buf,i,PROTO_EXCHANGE_TIMEOUT,0);
	if( len != i )
	{
		DEBUG_DUMP("接收socks5 协商包失败,想接收%d,收到:%d\n",len,i);
		return -1;
	}
	for( i = 0;i< len && buf[i];i++ );
	if( i == len )
	{
		DEBUG_DUMP("用户没有请求socks5 无认证方法:\n");
		return -1;
	}
	buf[0] = 5;
	buf[1] = 0;
	if( send(sd,(char*)buf,2,0) != 2)
		return -1;
	len = 5;
	WAIT_AND_RECV(sd,(char*)buf,len,PROTO_RECVRESP_TIMEOUT,0);
	if( len != 5 || buf[0] != 5 || buf[1] != 1 )
	{
		DEBUG_DUMP(" 处理socks5CONNECT 命令失
				败:len:%d,buf[0]:0x%x,buf[1]:0x%x\n",len,buf[0],buf[1]);
		return -1;
	}
	switch( buf[3] )
	{
		case 1: // 是IP 地址
			len = 5;
			WAIT_AND_RECV(sd,(char*)buf+5,len,PROTO_RECVRESP_TIMEOUT,0
				     );
			if( len != 5 ){
				DEBUG_DUMP(" 处理socks5CONNECT 命令[IP 方式] 失
						败:len:%d\n",len);
				return -1;
			}
			{
				struct in_addr addr;
				memcpy((char*)&addr.s_addr,buf+4,4);
				strcpy(dstaddr,inet_ntoa(addr));
				dstport = ntohs(*(unsigned short*)(buf+8));
			}
			break;
		case 3: // 是域方式
			len = buf[4]+2;
			WAIT_AND_RECV(sd,(char*)buf+5,len,PROTO_RECVRESP_TIMEOUT,0
				     );
			if( len != buf[4]+2 ){
				DEBUG_DUMP(" 处理socks5CONNECT 命令[ 域方式] 失
						败:len:%d\n",len);
				return -1;
			}
			memcpy(dstaddr,buf+5,buf[4]);
			dstaddr[buf[4]] = 0;
			dstport = ntohs(*(unsigned short*)(buf+5+buf[4]));
			break;
		default:
			DEBUG_DUMP(" 处理socks5CONNECT 命令[] 失败: 未知方式:type:0x%x\n",buf[3]);
			return -1;
	}
	return httpproxy_connect(proxyaddr,proxyport,dstaddr,dstport);
}

int listenport(int port,const char*addr)
{
	int len = sizeof(struct sockaddr_in);
	struct sockaddr_in bindaddr;
	int sd = socket(AF_INET,SOCK_STREAM,0);
	if( sd == -1)
		return -1;
	memset(&bindaddr,0,len);
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(port);
	if( addr && addr[0] )
		bindaddr.sin_addr.s_addr = inet_addr(addr);
	if( bind ( sd,(struct sockaddr*)&bindaddr,&len) || listen(sd,100 ))
	{
		DEBUG_DUMP("打开端口失败,port:%d\n",port);
		CLOSESOCKET(sd);
		return -1;
	}
	return sd;
}


void running(int sd)
{
	int ad;
	if( sd == -1 )
		return;
	while(1)
	{
		int proxyid;
		char buf[10240];
		int len;
		int maxid;
		int actcount;
		ad = accept(sd,NULL,NULL);
		if( ad == -1 )
			break;
		DEBUG_DUMP("有客户连接,id:%d\n",ad);
		if((proxyid = socks5_accept(ad,"172.16.68.21",80)) == -1 )
		{
			CLOSESOCKET(ad);
			continue;
		}
		// 进行代理转发工作
		maxid = ad > proxyid ? ad:proxyid;
		while( ad > -1 )
		{
			struct timeval waittime = {10,0};
			struct fd_set sset;
			FD_ZERO(&sset);
			FD_SET(ad,&sset);
			FD_SET(proxyid,&sset);
			actcount = select(maxid+1,&sset,NULL,NULL,&waittime);
			while(actcount > 0 )
			{
				int actid = FD_ISSET(proxyid,&sset)?proxyid:ad;
				int sendid = actid == ad? proxyid:ad;
				FD_CLR(actid,&sset);
				len = sizeof(buf)-1;
				WAIT_AND_RECV(actid,buf,len,10,0);
				if( len > 0 )
				{
					buf[len] = 0;
					send(sendid,buf,len,0);
					DEBUG_DUMP("%d 接口活动,内容为:%s\n",actid,buf);
				}
				else
				{
					DEBUG_DUMP("接收失败,id:%d\n",actid);
					CLOSESOCKET(ad);
					ad = -1;
					break;
				}
				actcount --;
			}
		}
		// 某一方已经关闭,继续下一组转发
		CLOSESOCKET(proxyid);
	}
	CLOSESOCKET(sd);
}

int main(int, char**)
{
	int ld;
	INIT_SOCKET();
	ld = listenport(1080,NULL);
	if( ld != -1)
		running(ld);
	else
		DEBUG_DUMP("监听失败\n");
	CLEAN_SOCKET();
}
