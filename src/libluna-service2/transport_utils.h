/* @@@LICENSE
*
*      Copyright (c) 2008-2014 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */


#ifndef _TRANSPORT_UTILS_H_
#define _TRANSPORT_UTILS_H_

#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>

#include "log.h"

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

extern int _ls_debug_tracing;

#define DEBUG_TRACING (_ls_debug_tracing)
#define DEBUG_VERBOSE (_ls_debug_tracing > 1)

int strlen_safe(const char *str);
void DumpHashItem(gpointer key, gpointer value, gpointer user_data);
void DumpHashTable(GHashTable *table);
bool _LSTransportSetupSignalHandler(int signal, void (*handler)(int));
void _LSTransportFdSetBlock(int fd, bool *prev_state_blocking);
void _LSTransportFdSetNonBlock(int fd, bool *prev_state_blocking);
const char *_LSGetHubLocalSocketAddress(bool is_public_bus);
const char *_LSGetHubLocalSocketDirectory(bool is_public_bus);

/* compile-time type check */
#define TYPECHECK(type,val)             \
({	type __type;                        \
	typeof(val) __val;                  \
	(void)(&__type == &__val);          \
	1;                                  \
})

#define LOCK(name, mutex)                                   \
do {                                                        \
    LOG_LS_TRACE("%s: LOCK %s\n", __func__, name);          \
    pthread_mutex_lock(mutex);                              \
} while (0)

#define UNLOCK(name, mutex)                                 \
do {                                                        \
    LOG_LS_TRACE("%s: UNLOCK %s\n", __func__, name);        \
    pthread_mutex_unlock(mutex);                            \
} while (0)


#define TRANSPORT_LOCK(mutex)                               \
do {                                                        \
    LOCK("Transport", mutex);                               \
} while (0)

#define TRANSPORT_UNLOCK(mutex)                             \
do {                                                        \
    UNLOCK("Transport", mutex);                             \
} while (0)

#define SERIAL_INFO_LOCK(mutex)                             \
do {                                                        \
    LOCK("Serial Info", mutex);                             \
} while (0)

#define SERIAL_INFO_UNLOCK(mutex)                           \
do {                                                        \
    UNLOCK("Serial Info", mutex);                           \
} while (0)

#define GLOBAL_TOKEN_LOCK(mutex)                            \
do {                                                        \
    LOCK("Global Token", mutex);                            \
} while (0)

#define GLOBAL_TOKEN_UNLOCK(mutex)                          \
do {                                                        \
    UNLOCK("Global Token", mutex);                          \
} while (0)

#define OUTGOING_LOCK(mutex)                                \
do {                                                        \
    LOCK("Outgoing", mutex);                                \
} while (0)

#define OUTGOING_UNLOCK(mutex)                              \
do {                                                        \
    UNLOCK("Outgoing", mutex);                              \
} while (0)

#define OUTGOING_SERIAL_LOCK(mutex)                         \
do {                                                        \
    LOCK("Outgoing Serial", mutex);                         \
} while (0)

#define OUTGOING_SERIAL_UNLOCK(mutex)                       \
do {                                                        \
    UNLOCK("Outgoing Serial", mutex);                       \
} while (0)

#define INCOMING_LOCK(mutex)                                \
do {                                                        \
    LOCK("Incoming", mutex);                                \
} while (0)

#define INCOMING_UNLOCK(mutex)                              \
do {                                                        \
    UNLOCK("Incoming", mutex);                              \
} while (0)


#endif  // _TRANSPORT_UTILS_H_
