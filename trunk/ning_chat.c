/*
 *  ning_chat.c
 *  pidgin-ning
 *
 *  Created by MyMacSpace on 6/08/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#include "ning_chat.h"

//list buddies
//send message to chat
//send whisper
//poll for messages
//fetch chat history
//join chat

/*
void (*chat_leave)(PurpleConnection *, int id);
void (*chat_whisper)(PurpleConnection *, int id, const char *who, const char *message);
int  (*chat_send)(PurpleConnection *, int id, const char *message, PurpleMessageFlags flags);
void (*join_chat)(PurpleConnection *, GHashTable *components);
PurpleConversation* purple_find_chat(const PurpleConnection *gc, int id);
 */

typedef struct _NingChat {
	NingAccount *na;
	gchar *roomId;
	gint purple_id;
	gchar *ning_hash;
	
	guint userlist_timer;
	guint message_poll_timer;
} NingChat;

void
ning_chat_get_history_cb(NingAccount *na, gchar *response, gsize len, gpointer userdata)
{
	NingChat *chat;
	
	chat = userdata;
}

gboolean
ning_chat_get_history(NingChat *chat)
{
	
}

void
ning_chat_get_users_cb(NingAccount *na, gchar *response, gsize len, gpointer userdata)
{
	NingChat *chat;
	JsonObject *obj;
	
	chat = userdata;
	obj = ning_json_parse(response, len);
}

gboolean
ning_chat_get_users(NingChat *chat)
{
	NingAccount *na;
	gchar *postdata;
	gchar *encoded_hash;
	gchar *encoded_app;
	gchar *encoded_id;
	gchar *encoded_token;
	gchar *encoded_room;
	
	na = chat->na;
	
	encoded_hash = g_strdup(purple_url_encode(chat->ning_hash));
	encoded_app = g_strdup(purple_url_encode(na->ning_app));
	encoded_id = g_strdup(purple_url_encode(na->ning_id));
	encoded_token = g_strdup(purple_url_encode(na->chat_token));
	encoded_room = g_strdup(purple_url_encode(chat->roomId));
	
	postdata = g_strdup_printf("h=%s&a=%s&i=%s&t=%s&r=%s", encoded_hash, encoded_app,
							   encoded_id, encoded_token, encoded_room);
	
	ning_post_or_get(na, NING_METHOD_POST, na->chat_domain,
					 "/xn/presence/list", postdata, 
					 ning_chat_get_users_cb, chat, FALSE);
	
	g_free(postdata);
	g_free(encoded_room);
	g_free(encoded_token);
	g_free(encoded_id);
	g_free(encoded_app);
	g_free(encoded_hash);
	
	return TRUE;
}

void
ning_chat_poll_messages_cb(NingAccount *na, gchar *response, gsize len, gpointer userdata)
{
	NingChat *chat;
	
	chat = userdata;
}

gboolean
ning_chat_poll_messages(NingChat *chat)
{
	
}

void
ning_chat_cb(NingAccount *na, gchar *response, gsize len, gpointer userdata)
{
	PurpleConversation *conv;
	
	conv = userdata;
}

void
ning_chat_whisper(PurpleConnection *pc, int id, const char *who, const char *message)
{
	NingAccount *na;
	gchar *stripped;
	PurpleConversation *conv;
	gchar *postdata;
	gchar *message_json;
	
	gchar *message_escaped;
	gchar *ning_id_escaped;
	gchar *token_escaped;
	gchar *room_escaped;
	gchar *app_escaped;
	
	na = pc->proto_data;
	conv = purple_find_chat(pc, id);
	
	app_escaped = g_strdup(purple_url_encode(na->ning_app));
	token_escaped = g_strdup(purple_url_encode(na->xg_token));
	room_escaped = g_strdup(purple_url_encode(conv->name));
	ning_id_escaped = g_strdup(purple_url_encode(na->ning_id));
	
	stripped = purple_markup_strip_html(message);
	message_json = g_strdup_printf("{ \"roomId\":\"%s\", \"type\":\"%s\", \"targetId\":\"%s\", \"body\":\"%s\" }",
									  conv->name, (who?"private":"message"),
									  (who?who:"null"), stripped);
	message_escaped = g_strdup(purple_url_encode(message_json));
	
	postdata = g_strdup_printf("a=%s&i=%s&t=%s&r=%s&message=%s",
							   app_escaped, ning_id_escaped,
							   token_escaped, room_escaped,
							   message_escaped);
	
	ning_post_or_get(na, NING_METHOD_POST, na->chat_domain,
					 "/xn/groupchat/publish", postdata, 
					 ning_chat_cb, conv, FALSE);
	
	g_free(postdata);
	g_free(message_escaped);
	g_free(message_json);
	g_free(stripped);
	g_free(app_escaped);
	g_free(ning_id_escaped);
	g_free(token_escaped);
	g_free(room_escaped);
}

int
ning_chat_send(PurpleConnection *pc, int id, const char *message, PurpleMessageFlags flags)
{
	if (flags != PURPLE_MESSAGE_SEND)
		return -1;
	
	ning_chat_whisper(pc, id, NULL, message);
	return 1;
}

void
ning_join_chat_by_name(NingAccount *na, const gchar *roomId)
{
	NingChat *chat;
	
	if (na == NULL || roomId == NULL)
		return;
	
	chat = g_new0(NingChat, 1);
	chat->na = na;
	chat->roomId = roomId;
	chat->purple_id = g_str_hash(roomId);
	chat->ning_hash = "null";
	
	serv_got_joined_chat(na->pc, g_str_hash(roomId), roomId);
	
	//get history
	ning_chat_get_history(chat);
	
	//get user list
	ning_chat_get_users(chat);
	chat->userlist_timer = purple_timeout_add_seconds(60, ning_chat_get_users);
	
	//start message poll
	ning_chat_poll_messages(chat);
	chat->message_poll_timer = purple_timeout_add_seconds(180, ning_chat_poll_messages);
}

void 
ning_join_chat(PurpleConnection *pc, GHashTable *components)
{
	NingAccount *na;
	
	if (pc == NULL || pc->proto_data == NULL || components == NULL)
		return;
	
	na = pc->proto_data;
	ning_join_chat_by_name(na, g_hash_table_lookup(components, "name"));
}
