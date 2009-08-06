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
	if (na == NULL || roomId == NULL)
		return;
	
	serv_got_joined_chat(na->pc, g_str_hash(roomId), roomId);
	
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
