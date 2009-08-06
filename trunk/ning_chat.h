/*
 *  ning_chat.h
 *  pidgin-ning
 *
 *  Created by MyMacSpace on 6/08/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */


#ifndef NING_CHAT_H
#define NING_CHAT_H

#include "libning.h"
#include "ning_connection.h"

void ning_chat_whisper(PurpleConnection *pc, int id, const char *who, const char *message);
int ning_chat_send(PurpleConnection *pc, int id, const char *message, PurpleMessageFlags flags);
void ning_join_chat_by_name(NingAccount *na, const gchar *roomId);
void ning_join_chat(PurpleConnection *pc, GHashTable *components);

#endif /* NING_CHAT_H */
