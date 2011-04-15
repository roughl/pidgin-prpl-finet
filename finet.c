/*
 * Finet Protocol Plugin
 *
 * Copyright (C) 2010
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* config.h may define PURPLE_PLUGINS; protect the definition here so that we
 * don't get complaints about redefinition when it's not necessary. */
#ifndef PURPLE_PLUGINS
# define PURPLE_PLUGINS
#endif

#define _(arg) arg

#include <glib.h>

/* This will prevent compiler errors in some instances and is better explained in the
 * how-to documents on the wiki */
#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

#include <osxcart/osxcart/rtf.h>
#include <unistd.h>
#include <pth.h>
#include <errno.h>
#include <string.h>
#include "finet.h"
#include "dnssrv.h"
#include "accountopt.h"
#include "blist.h"
#include "cmds.h"
#include "conversation.h"
#include "connection.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "roomlist.h"
#include "status.h"
#include "util.h"
#include "version.h"


#define FINET_STATUS_ONLINE   "online"
#define FINET_STATUS_AWAY     "away"
#define FINET_STATUS_OFFLINE  "offline"

#define FINETPRPL_ID "prpl-finet"

/* we're adding this here and assigning it in plugin_load because we need
 * a valid plugin handle for our call to purple_notify_message() in the
 * plugin_action_test_cb() callback function */
static PurplePlugin *finet_plugin = NULL;

/* This function is the callback for the plugin action we added. All we're
 * doing here is displaying a message. When the user selects the plugin
 * action, this function is called. */
static void
plugin_action_test_cb (PurplePluginAction * action)
{
	purple_notify_message (finet_plugin, PURPLE_NOTIFY_MSG_INFO,
		_("Plugin Actions Test"), "This is a plugin actions test :)", NULL, NULL,
		NULL);
}

/* we tell libpurple in the PurplePluginInfo struct to call this function to
 * get a list of plugin actions to use for the plugin.  This function gives
 * libpurple that list of actions. */
static GList *
plugin_actions (PurplePlugin * plugin, gpointer context)
{
	/* some C89 (a.k.a. ANSI C) compilers will warn if any variable declaration
	 * includes an initilization that calls a function.  To avoid that, we
	 * generally initialize our variables first with constant values like NULL
	 * or 0 and assign to them with function calls later */
	GList *list = NULL;
	PurplePluginAction *action = NULL;

	/* The action gets created by specifying a name to show in the UI and a
	 * callback function to call. */
	action = purple_plugin_action_new ("Plugin Action Test", plugin_action_test_cb);

	/* libpurple requires a GList of plugin actions, even if there is only one
	 * action in the list.  We append the action to a GList here. */
	list = g_list_append (list, action);

	/* Once the list is complete, we send it to libpurple. */
	return list;
}

static gboolean
plugin_load (PurplePlugin * plugin)
{
	purple_notify_message (plugin, PURPLE_NOTIFY_MSG_INFO, "Hello World!",
		"This is the Hello World! plugin :)", NULL, NULL,
		NULL);

	finet_plugin = plugin; /* assign this here so we have a valid handle later */

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin * plugin)
{
	return TRUE;
}

static void
finet_close(PurpleConnection* gc)
{
	FinetSession* session;
	purple_debug_info("finet", "close\n" );
	session = gc->proto_data;
	if(session != NULL) {
		purple_debug_info("finet", "session not NULL: %p\n", session);
		if(session->inpa) {
			purple_input_remove( session->inpa );
			session->inpa = 0;
		}
		if(session->connection) {
			close(session->connection);
			session->connection = 0;
		}
		g_free(session);
		session = NULL;
		gc->proto_data = NULL;
	}
	return;
}

static gssize
finet_send_msg(FinetSession* session, EFinetCodes code, const char* userId, const char* data)
{
	char *buf = 0;
	int i;
	int offset;
	int size;
	gssize ret;
	
	glong nData;
	glong nUserId;

	gunichar2* data_16;
	gunichar2* userId_16;

	userId_16 = g_utf8_to_utf16( userId, 255, NULL, &nUserId, NULL ); // a maximum of 255 bytes allowed for userId
	data_16 = g_utf8_to_utf16( data, -1, NULL, &nData, NULL );

	if( userId_16 == NULL || data_16 == NULL )
	{
		purple_debug_error( "finet", "could not convert %s %s to UTF16\n", userId, data );
		ret = -1000;
		goto out;
	}
	
	size = 8+2*nUserId+2*nData;

	buf = g_new0(char, size);
	// @todo check for buf
	buf[0] = FINET_CLIENT_MAGIC1;
	buf[1] = FINET_CLIENT_MAGIC2;
	*((guint32 *)&buf[2]) = nData;
	buf[6] = (guint8)nUserId;
	buf[7] = code;

	offset = 8;

	for(i=0; i<(2*nUserId); i++)
	{
		buf[offset] = ((char *)userId_16)[i];
		offset++;
	}
	for(i=0; i<(2*nData); i++)
	{
		buf[offset] = ((char *)data_16)[i];
		offset++;
	}
	ret = write(session->connection, buf, size);
	purple_debug_info("finet", "sent userId: %s (%ld) data: %s (%ld), tot: %"G_GSSIZE_FORMAT "\n", userId, 2*nUserId, data, 2*nData, ret);

out:
	g_free(buf);
	g_free(userId_16);
	g_free(data_16);
	return ret;
}

static void
finet_auth_cb( gpointer user_data )
{
	ContactInvite* invite = (ContactInvite *)user_data;
	purple_debug_info( "finet", "send auth response\n" );

	finet_send_msg( invite->session, eFinetFriendshipAccept, invite->userId, "Yes" );

	g_free( invite->userId );
	g_free( invite );
}

static void
finet_deny_cb( gpointer user_data )
{
	ContactInvite* invite = (ContactInvite *)user_data;
	purple_debug_info( "finet", "send deny response\n" );
	
	finet_send_msg( invite->session, eFinetFriendshipAccept, invite->userId, "No" );

	g_free( invite->userId );
	g_free( invite );
}

static void
finet_handle_msg( FinetSession* session, FinetMsg msg )
{
	switch(msg.code)
	{
	case eFinetSrvLoginResponse: {
		purple_debug_info("finet", "received server login response\n");
		if(strcmp(msg.userId, "OK") == 0) {
			purple_connection_set_state(session->gc, PURPLE_CONNECTED);
			finet_send_msg(session, eFinetKeepAlive, "", "60"); // set keep alive interval on server
		}
		else if(strcmp(msg.userId, "wrongPW") == 0) {
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("wrong password"));
		}
		else if(strcmp(msg.userId, "wrongUserID") == 0) {
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, _("wrong username"));
		}
		else {
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, msg.userId);
		}
		break;
	}

	case eFinetSrvLoadFriendList: {
		PurpleBuddy *b;
		purple_debug_info("finet", "received LoadFriendList %s -> %s\n", msg.userId, msg.data);
		// '?' Indicates a not yet accepted friendship request
		if( msg.userId[0] == '?' ) {
			ContactInvite *invite;
			invite = g_new0( ContactInvite, 1);
			invite->session = session;
			invite->userId = g_strdup(&msg.userId[1]);
			b = purple_find_buddy(session->acct, &msg.userId[1] );
			if( b ) {
				//b = purple_buddy_new(session->acct, &msg.userId[1], msg.data );
				//purple_blist_add_buddy(b, NULL, NULL, NULL);
				purple_account_request_authorization( session->acct, &msg.userId[1], NULL,
						msg.data, NULL, TRUE, finet_auth_cb, finet_deny_cb, invite );
			}
			else {
				purple_account_request_authorization( session->acct, &msg.userId[1], NULL,
						msg.data, NULL, FALSE, finet_auth_cb, finet_deny_cb, invite );
			}
		}
		// '*' Indicates that this user not yet accepted your friendship request
		else if( msg.userId[0] == '*' ) {
			b = purple_find_buddy(session->acct, &msg.userId[1] );
			if( b==NULL ) {
				b = purple_buddy_new(session->acct, &msg.userId[1], msg.data );
				purple_blist_add_buddy(b, NULL, NULL, NULL);
			}
		}
		// ':' Indicates that a user accepted your friendship request just now
		else if( msg.userId[0] == ':' ) {
			b = purple_find_buddy(session->acct, &msg.userId[1] );
			if( b==NULL ) {
				b = purple_buddy_new(session->acct, &msg.userId[1], msg.data );
				purple_blist_add_buddy(b, NULL, NULL, NULL);
			}
		}
		else
		{
			b = purple_find_buddy(session->acct, msg.userId );
			if( b==NULL ) {
				b = purple_buddy_new(session->acct, msg.userId, msg.data );
				purple_blist_add_buddy(b, NULL, NULL, NULL);
			}
		}
		break;
	}

	case eFinetSrvAutoLogoff: {
		purple_debug_info("finet", "received AutoLogoff\n");
		purple_account_disconnect( session->acct );
		break;
	}

	case eFinetSrvFriendOnline: {
		purple_debug_info("finet", "Friend %s got online\n", msg.userId);
        purple_prpl_got_user_status(session->acct, msg.userId, FINET_STATUS_ONLINE,
                                  "message", _("Message"), NULL);
		break;
	}

	case eFinetSrvFriendOffline: {
		purple_debug_info("finet", "Friend %s got offline\n", msg.userId);
        purple_prpl_got_user_status(session->acct, msg.userId, FINET_STATUS_OFFLINE,
                                  "message", _("Message"), NULL);
		break;
	}

	case eFinetSrvChatMessage: {
		GtkTextBuffer* buffer = NULL;
		GError *error = NULL;
		buffer = gtk_text_buffer_new(NULL);
		if( rtf_text_buffer_import_from_string( buffer, msg.data, &error ) ) {
			GtkTextIter *start = g_new(GtkTextIter, 1);
			GtkTextIter *end = g_new(GtkTextIter, 1);
			gtk_text_buffer_get_start_iter( buffer, start );
			gtk_text_buffer_get_end_iter( buffer, end );
			
			gchar * data = gtk_text_buffer_get_text(buffer, start, end, FALSE);
			if( data )
			{
				serv_got_im(session->gc, msg.userId, data, PURPLE_MESSAGE_RECV, time(NULL) );
				g_free(data);
			}
			g_free(start);
			g_free(end);
		}
		else {
			purple_debug_error("finet", "Converting received data from RTF failed\n");
		}
		break;
	}
	

	case eFinetSrvNicknameChanged: {
		purple_debug_info("finet", "Friend %s changed nickname to %s\n", msg.userId, msg.data);
		break;
	}

	case  eFinetSrvFriendshipRequestResp: {
		purple_debug_info("finet", "Friendship Request Response %s, %s\n", msg.userId, msg.data);
		break;
	}
	case  eFinetSrvFriendshipEnded: {
		purple_debug_info("finet", "Friendship Ended: %s, %s\n", msg.userId, msg.data);
		break;
	}

	case eFinetSrvClientInfo: {
		purple_debug_info("finet", "Client Info requested: %s, %s\n", msg.userId, msg.data);
		if( strcmp(msg.userId, FINET_CLIENT_INFO_VERSION) == 0 ) {
			finet_send_msg(session, eFinetClientInfoResponse, FINET_CLIENT_INFO_VERSION, "Pidgin Finet " FINET_PLUGIN_VERSION ); 
		}
		break;
	}

	case  eFinetSrvStartTyping: {
		purple_debug_info("finet", "%s started typing: %s \n", msg.userId, msg.data);
		serv_got_typing( session->gc, msg.userId, 0, PURPLE_TYPING);
		break;
	}
	case  eFinetSrvStopTyping: {
		purple_debug_info("finet", "%s stoped  typing: %s \n", msg.userId, msg.data);
		serv_got_typing_stopped( session->gc, msg.userId);
		break;
	}

	default:
		purple_debug_info("finet","unknown: %s %s\n", msg.userId, msg.data);
		break;
	}
}

static void
read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	FinetSession *session = data;
	gssize len;

	if( cond != PURPLE_INPUT_READ )
		return;

	session->acct->gc->last_received = time(NULL);
	if( session->buf == 0) {
		len = recv(session->connection, session->header_buf, 8, MSG_PEEK);
		// no more data available
		if(len == -1 && errno == EAGAIN) {
			purple_debug_info("finet", "no more data to read\n");
			return;
		}
		if (len <= 0) {
			purple_debug_error("finet", "connection read error, "
				"len: %" G_GSSIZE_FORMAT "\n",
				len );
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("connection read error"));
			return;
		}
		purple_debug_info("finet", "got pkg");
		if(len < 8) {
			return;
		}
		if( session->header_buf[0] != FINET_SERV_MAGIC1 ||
			session->header_buf[1] != FINET_SERV_MAGIC2 )
		{
			purple_debug_error("finet", "wrong magic number in server pkg\n");
			return;
		}
		session->dataLength = *((guint32 *)&session->header_buf[2]);
		session->userIdLength = session->header_buf[6];
		session->msg.code = session->header_buf[7];
		len = read(session->connection, session->header_buf, 8);
		if( len < 8 ) {
			purple_debug_error("finet", "received mal formed msg\n");
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("received mal formed msg"));
			return;
		}

		// @TODO what happens if both dataLength and userIdLength are 0?
		session->buf = g_new0(char, session->dataLength*2 + session->userIdLength*2);
		purple_debug_info("finet", "header complete: code: %i, dataLen: %li, useridLen: %i\n", session->msg.code, session->dataLength, session->userIdLength);
	}
	else {
		glong nRead;
		glong nWrite;
		len = recv(session->connection, session->buf, session->userIdLength*2 + session->dataLength*2, MSG_PEEK );
		// no more data available
		if(len == -1 && errno == EAGAIN) {
			purple_debug_info("finet", "no more data to read\n");
			return;
		}
		if (len <= 0) {
			purple_debug_error("finet", "connection read error, "
				"len: %" G_GSSIZE_FORMAT "\n",
				len );
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("connection read error"));
			goto out_buf;
		}
		// message not yet available
		if( len < session->userIdLength*2 + session->dataLength*2 ) {
			purple_debug_info("finet", "message not yet available: %"G_GSSIZE_FORMAT" of %li\n", len, session->userIdLength*2 + session->dataLength*2);
			return;
		}
		if(session->userIdLength == 0) {
			session->msg.userId = g_strdup("");
		}
		else {
			len = read(session->connection, session->buf, session->userIdLength*2);
			if(len<session->userIdLength*2)
				goto out_buf;
			session->msg.userId = g_utf16_to_utf8((const gunichar2 *)session->buf, session->userIdLength, &nRead, &nWrite, NULL);
		}

		if(session->dataLength == 0) {
			session->msg.data = g_strdup("");
		}
		else {
			len = read(session->connection, &session->buf[session->userIdLength*2], session->dataLength*2);
			if(len<session->dataLength*2)
				goto out_userId;
			session->msg.data = g_utf16_to_utf8((const gunichar2 *)&session->buf[session->userIdLength*2], session->dataLength, &nRead, &nWrite, NULL);
		}

		finet_handle_msg( session, session->msg );

		
		g_free(session->msg.data);
		session->msg.data = 0;
out_userId:
		g_free(session->msg.userId);
		session->msg.userId = 0;
out_buf:
		g_free(session->buf);
		session->oldbuf = session->buf;
		session->buf = 0;
	}
}

static void
connect_cb(gpointer data, gint source, const char *error_message)
{
	gssize ret = 0;
	FinetSession* session = data;
	purple_connection_update_progress(session->gc, _("Connected"),
									1,   /* which connection step this is */
									FINET_LOGIN_STEPS);  /* total number of steps */
	session->connection = source;
	if( source >= 0)
	{
		const char *username;
		const char *password;
		username = purple_account_get_username(session->acct);
		password = purple_connection_get_password(session->gc);

		// register read callback
		session->inpa = purple_input_add(session->connection, PURPLE_INPUT_READ, read_cb, data);

		ret = finet_send_msg(session, eFinetCodeLogin, username, password);
		purple_debug_info("finet", "Data sent\n");
		purple_connection_update_progress(session->gc, _("Send login data"),
										2,   /* which connection step this is */
										FINET_LOGIN_STEPS);  /* total number of steps */
	}
	else
	{
		purple_debug_error("finet", "Connection error: %s\n", error_message);
		purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection error"));
	}
}

static void
finet_login(PurpleAccount* acct)
{
	FinetSession* session; 
	int port;
	const char *host;
	PurpleConnection *gc;

	session = g_new0(FinetSession, 1);
	session->inpa = 0;
	session->acct = acct;
	gc = purple_account_get_connection(acct);
	session->gc = gc;
	gc->proto_data = session;
	purple_debug_info("finet", "logging in %s\n", acct->username);
	purple_connection_update_progress(gc, _("Connecting"),
									0,   /* which connection step this is */
									FINET_LOGIN_STEPS);  /* total number of steps */


	host = purple_account_get_string(acct, "host", FINET_SERVER);
	port = purple_account_get_int(acct, "port", FINET_PORT);

	purple_debug_info("finet", "connect(%s, %i)\n", host, port);
	session->connect_data = purple_proxy_connect(NULL, acct, host, port, connect_cb, session);
	
	return;
}

static GList*
finet_status_types(PurpleAccount* acct)
{
	GList *types = NULL;
	PurpleStatusType *type;

	purple_debug_info("finet", "returning status types for %s: %s, %s, %s\n",
					acct->username,
					FINET_STATUS_ONLINE, FINET_STATUS_AWAY, FINET_STATUS_OFFLINE);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
	  FINET_STATUS_ONLINE, NULL, TRUE, TRUE, FALSE,
	  "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
	  NULL);
	types = g_list_prepend(types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
	  FINET_STATUS_AWAY, NULL, TRUE, TRUE, FALSE,
	  "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
	  NULL);
	types = g_list_prepend(types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE,
	  FINET_STATUS_OFFLINE, NULL, TRUE, TRUE, FALSE,
	  "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
	  NULL);
	types = g_list_prepend(types, type);

	return g_list_reverse(types);
}

static const char*
finet_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	purple_debug_info("finet", "finet_list_icon()\n");
	return "finet";
}

static void
finet_add_buddy( PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group )
{
	purple_debug_info("finet", "adding %s to %s's buddy list\n",
		buddy->name, gc->account->username);
	finet_send_msg( gc->proto_data, eFinetFriendshipRequest, buddy->name, "" );
}

static void
finet_remove_buddy( PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group )
{
	purple_debug_info("finet", "removing %s from %s's buddy list\n",
		buddy->name, gc->account->username);
	finet_send_msg( gc->proto_data, eFinetFriendshipEnd, buddy->name, "" );
}

static void
finet_keepalive(PurpleConnection *gc)
{	
	purple_debug_info("finet", "sending keep alive\n");
	finet_send_msg(gc->proto_data, eFinetKeepAlive, "", "");
	return;
}

static int 
finet_send_im( PurpleConnection* gc, const char *who, const char *message, PurpleMessageFlags flags)
{
	GtkTextBuffer* buffer;
	gchar *rtf_text;
	int retval = 0;
	purple_debug_info("finet", "send IM %s to %s\n", message, who);
	buffer = gtk_text_buffer_new(NULL);
	gtk_text_buffer_set_text( buffer, message, -1);
	rtf_text = rtf_text_buffer_export_to_string( buffer );
	if( rtf_text )
	{
		retval = finet_send_msg( gc->proto_data, eFinetChatMessage, who, rtf_text);
		g_free(rtf_text);
	}
	else
	{
		purple_debug_error("finet", "converting IM %s to RTF failed\n", message );
		retval = -1000;
	}
	return retval;
}

static unsigned int
finet_send_typing( PurpleConnection* gc, const char *name, PurpleTypingState state)
{
	switch(state)
	{
		case PURPLE_TYPING:
			finet_send_msg( gc->proto_data, eFinetStartTyping, name, "");
			break;
		case PURPLE_TYPED:
			finet_send_msg( gc->proto_data, eFinetStopTyping, name, "");
			break;
		case PURPLE_NOT_TYPING:
			// nothing
			break;
	}
	return 0;
}

PurplePluginProtocolInfo prpl_info = {
	//OPT_PROTO_REGISTER_NOSCREENNAME|OPT_PROTO_CHAT_TOPIC|OPT_PROTO_SLASH_COMMANDS_NATIVE,
	0,  /* options */
	NULL,                /* user_splits */
	NULL,                /* protocol_options */
	{"png,gif,jpeg", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_SEND}, /* icon_spec */
	finet_list_icon,     /* list_icon */
	NULL,//finet_list_emblem,   /* list_emblem */
	NULL,//finet_status_text,   /* status_text */
	NULL,//finet_tooltip_text,  /* tooltip_text */
	finet_status_types,  /* status_types */
	NULL,//finet_node_menu,     /* blist_node_menu */
	NULL,//finet_join_chat_info,/* chat_info */
	NULL,//finet_join_chat_info_defaults,/* chat_info_defaults */
	finet_login,         /* login */
	finet_close,         /* close */
	finet_send_im,       /* send_im */
	NULL,                /* set_info */
	finet_send_typing,   /* send_typing */
	NULL,//finet_get_info,      /* get_info */
	NULL,//finet_set_status,    /* set_status */
	NULL,//finet_set_idle,      /* set_idle */
	NULL,                /* change_passwd */
	finet_add_buddy,     /* add_buddy */
	NULL,                /* add_buddies */
	finet_remove_buddy,  /* remove_buddy */
	NULL,                /* remove_buddies */
	NULL,//finet_add_permit,    /* add_permit */
	NULL,//finet_add_deny,      /* add_deny */
	NULL,//finet_rem_permit,    /* rem_permit */
	NULL,//finet_rem_deny,      /* rem_deny */
	NULL,                /* set_permit_deny */
	NULL,//finet_join_chat,     /* join_chat */
	NULL,                /* reject chat invite */
	NULL,//finet_get_chat_name, /* get_chat_name */
	NULL,//finet_chat_invite,   /* chat_invite */
	/*finet_chat_leave*/NULL,    /* chat_leave */
	NULL,                /* chat_whisper */
	NULL,//finet_chat_send,     /* chat_send */
	finet_keepalive,     /* keepalive */
	NULL,                /* register_user */
	NULL,                /* get_cb_info */
	NULL,                /* get_cb_away */
	NULL,//finet_alias_buddy,   /* alias_buddy */
	NULL,//finet_group_buddy,   /* group_buddy */
	NULL,//finet_rename_group,  /* rename_group */
	NULL,//finet_buddy_free,    /* buddy_free */
	NULL,                /* convo_closed */
	NULL,//finet_normalize,     /* normalize */
	NULL,//finet_set_buddy_icon,/* set_buddy_icon */
	NULL,//finet_remove_group,  /* remove_group */
	/*finet_cb_real_name*/NULL,  /* get_cb_real_name */
	NULL,//finet_set_chat_topic,/* set_chat_topic */
	NULL,				 /* find_blist_chat */
	NULL,                /* roomlist_get_list */
	NULL,                /* roomlist_cancel */
	NULL,                /* roomlist_expand_category */
	NULL,                /* can_receive_file */
	NULL,                /* send_file */
	NULL,                /* new_xfer */
	NULL,//finet_offline_msg,   /* offline_message */
	NULL,                /* whiteboard_prpl_ops */
	NULL,//finet_send_raw,      /* send_raw */
	NULL,                /* roomlist_room_serialize */
	NULL,                /* unregister_user */
	NULL,                /* send_attention */
	NULL,                /* attention_types */
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL,                /* get_account_text_table */
	NULL,//finet_media_initiate,/* initiate_media */
	NULL,//finet_get_media_caps,/* can_do_media */
	NULL,                 /* get_moods */
	NULL,//finet_set_public_alias, /* set_public_alias */
	NULL,//finet_get_public_alias /* get_public_alias */
};

static void
finetprpl_destroy(PurplePlugin *plugin)
{
  purple_debug_info("finetprpl", "shutting down\n");
}

/* For specific notes on the meanings of each of these members, consult the C Plugin Howto
 * on the website. */
static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                                  /* type */
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	FINETPRPL_ID,
	"Finet",
	FINET_PLUGIN_VERSION,
	_("Finet protocol Plugin"),
	_("Implementation of the Finet protocol"),
	NULL, /* correct author */
	"http://www.example.com",
	plugin_load,
	plugin_unload,//plugin_unload
	finetprpl_destroy,//destroy
	NULL,//ui_info
	&prpl_info, // extra_info
	NULL, // prefs_info
	plugin_actions,		/* this tells libpurple the address of the function to call
						to get the list of plugin actions. */
	NULL, //padding
	NULL,
	NULL,
	NULL
};

static void
finet_init (PurplePlugin * plugin)
{
	PurpleAccountOption *option;
	
	option = purple_account_option_string_new("Server", "host", FINET_SERVER);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	
	option = purple_account_option_int_new("Port", "port", FINET_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
}

PURPLE_INIT_PLUGIN (finet, finet_init, info)
