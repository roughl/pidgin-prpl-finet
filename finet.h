
#ifndef FINET_H
#define FINET_H

#include "account.h"

#define FINET_SERV_MAGIC1 0x03
#define FINET_SERV_MAGIC2 0x49

#define FINET_CLIENT_MAGIC1 0x0D
#define FINET_CLIENT_MAGIC2 0xB0

#define FINET_PORT 443
#define FINET_SERVER "finet.dynalias.net"
#define FINET_HEADER_LEN 8

#define FINET_ALIAS_MAXLEN 100

#define FINET_USERID_MIN 4
#define FINET_USERID_MAX 20

#define FINET_PLUGIN_VERSION "0.1"

#define FINET_LOGIN_STEPS 3

#define FINET_CLIENT_INFO_VERSION "VERSION"
typedef enum {
	eFinetSrvLoginResponse         = 0x00,
	eFinetSrvLoadFriendList        = 0x01,
	eFinetSrvFriendOnline          = 0x02,
	eFinetSrvFriendOffline         = 0x03,
	eFinetSrvChatMessage           = 0x0A,
	eFinetSrvNicknameChanged       = 0x1E,
	eFinetSrvFriendshipRequestResp = 0x64,
	eFinetSrvFriendshipEnded       = 0x6E,
	eFinetSrvClientInfo            = 0x78,
	eFinetSrvNewAccountResponse    = 0xC8,

	eFinetSrvStartTyping           = 0x0B,
	eFinetSrvStopTyping            = 0x0C,
	eFinetSrvOfflineMessage        = 0x13,
	eFinetSrvStatusOnline          = 0x15,
	eFinetSrvStatusAway            = 0x16,
	eFinetSrvStatusBusy            = 0x17,
	eFinetSrvAutoLogoff            = 0xF0,

	eFinetSrvPhotoReceived         = 0x28,
	eFinetSrvPhotoChanged          = 0x29,
	eFinetSrvGroupChat             = 0x96,
	eFinetSrvProfileUpdated        = 0xD2,
	eFinetSrvProfileReceived       = 0xDC,
	eFinetSrvMyEmailRequestResponse= 0xE6,
	eFinetSrvEmailOrPWChangedResp  = 0xE7,

	eFinetSrvFileTransfer1         = 0x32,
	eFinetSrvFileTransfer2         = 0x33,
	eFinetSrvFileTransfer3         = 0x34,
	eFinetSrvFileTransfer4         = 0x35,
}EFinetServerCode;

typedef struct finet_msg {
	EFinetServerCode code;
	gchar* userId;
	gchar* data;
}FinetMsg;

typedef struct FinetSession {
	PurpleAccount *acct;
	PurpleConnection *gc;
	PurpleProxyConnectData *connect_data;
	int connection;
	guint inpa; // input handler
	char header_buf[FINET_HEADER_LEN];
	char *buf;
	char *oldbuf;
	glong dataLength;
	guint8 userIdLength;
	FinetMsg msg;
}FinetSession;

typedef struct ContactInvite {
	FinetSession *session;
	gchar *userId;
}ContactInvite;

typedef enum {
	eFinetCodeLogin = 0x00,
	eFinetKeepAlive = 0x09,
	eFinetStartTyping = 0x0B,
	eFinetChatMessage = 0x0A,
	eFinetStopTyping  = 0x0C,
	eFinetStatusOnline = 0x15,
	eFinetStatusAway   = 0x16,
	eFinetStatusBusy   = 0x17,
	eFinetChangeMyNickname = 0x1E,
	eFinetChangeMyPassword = 0xE8,
	eFinetFriendshipRequest = 0x64,
	eFinetFriendshipAccept  = 0x65,
	eFinetFriendshipEnd     = 0x6E,
	eFinetClientInfoResponse= 0x78,
	eFinetNewAccount        = 0xC8
}EFinetCodes;


#endif // FINET_H

