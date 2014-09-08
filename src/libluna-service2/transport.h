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


#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include <sys/stat.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>

#include <luna-service2/lunaservice.h>
#include "error.h"

typedef struct LSTransport _LSTransport;

#include "transport_message.h"
#include "transport_channel.h"
#include "transport_signal.h"
#include "transport_handlers.h"
#include "transport_serial.h"
#include "transport_outgoing.h"
#include "transport_incoming.h"
#include "transport_client.h"
#include "transport_security.h"
#include "transport_utils.h"

/* older versions of gcc only recognize __FUNCTION__ */
#if (__STDC_VERSION__ < 199901L)
# if (__GNUC__ >= 2)
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

#define STR(X)      #X
#define XSTR(X)     STR(X)

/* Example: to align 32-bit int, align_bytes should be 4 */
static inline unsigned int
PAD_TO_ALIGNMENT(unsigned int align_bytes, unsigned int size_bytes)
{
    /* only works if "align_bytes" is power of two */
    LS_ASSERT((align_bytes & (align_bytes - 1)) == 0);
    return (align_bytes + ((size_bytes - 1) & ~(align_bytes - 1)));
}

/* Don't use this directly; use the PADDING_BYTES_* macros */
static inline unsigned int
_padding_bytes(unsigned int align_bytes, unsigned int size_bytes)
{
    /* only works if ALIGNMENT is power of two */
    LS_ASSERT((align_bytes & (align_bytes - 1)) == 0);
    return (PAD_TO_ALIGNMENT(align_bytes, size_bytes) - size_bytes);
}

#define PADDING_BYTES_VAR(align_var, cur_len) _padding_bytes(sizeof(typeof(align_var)), cur_len)

#define PADDING_BYTES_TYPE(align_type, cur_len) _padding_bytes(sizeof(align_type), cur_len)

/**
 * Used to determine protocol compatibility when registering with the hub.
 * The value is an integer that should be incremented whenever the low level
 * message format changes.
 */
#define LS_TRANSPORT_PROTOCOL_VERSION   1

/* can override these with environment variable */
#define HUB_DEFAULT_INET_ADDRESS        192.168.2.101
#define DEFAULT_INET_PORT_PUBLIC        4411
#define DEFAULT_INET_PORT_PRIVATE       4412

/**
 * Address and port to connect to device emulator from the desktop
 * The emulator is set to bridge port 55NN to 44NN
 */
#define EMULATOR_DEFAULT_INET_ADDRESS   127.0.0.1
#define EMULATOR_INET_PORT_PUBLIC       5511    /*<< bridged port to emulator */
#define EMULATOR_INET_PORT_PRIVATE      5512    /*<< bridged port to emulator */

/** Running on the desktop and connecting to device */
#define HUB_INET_ADDRESS_PUBLIC         (XSTR(HUB_DEFAULT_INET_ADDRESS)":"XSTR(DEFAULT_INET_PORT_PUBLIC))
#define HUB_INET_ADDRESS_PRIVATE        (XSTR(HUB_DEFAULT_INET_ADDRESS)":"XSTR(DEFAULT_INET_PORT_PRIVATE))

/** Running on the emulator and connecting to emulator */
#define EMULATOR_INET_ADDRESS_PUBLIC    (XSTR(EMULATOR_DEFAULT_INET_ADDRESS)":"XSTR(DEFAULT_INET_PORT_PUBLIC))
#define EMULATOR_INET_ADDRESS_PRIVATE   (XSTR(EMULATOR_DEFAULT_INET_ADDRESS)":"XSTR(DEFAULT_INET_PORT_PRIVATE))

/** Running on the desktop and connecting to emulator */
#define EMULATOR_DESKTOP_INET_ADDRESS_PUBLIC    (XSTR(EMULATOR_DEFAULT_INET_ADDRESS)":"XSTR(EMULATOR_INET_PORT_PUBLIC))
#define EMULATOR_DESKTOP_INET_ADDRESS_PRIVATE   (XSTR(EMULATOR_DEFAULT_INET_ADDRESS)":"XSTR(EMULATOR_INET_PORT_PRIVATE))

#define HUB_LOCAL_SOCKET_DIRECTORY      DEFAULT_HUB_LOCAL_SOCKET_DIRECTORY
#define HUB_LOCAL_ADDRESS_PUBLIC_NAME   "com.palm.public_hub"
#define HUB_LOCAL_ADDRESS_PRIVATE_NAME  "com.palm.private_hub"

#define HUB_NAME                        "com.palm.hub"

#define MONITOR_NAME                    "com.palm.monitor"
#define MONITOR_NAME_PUB                "com.palm.monitor-pub"

/*
    Limits the number of times we will send an _LSTransportMessageTypeQueryName message to
    the hub for a dynamic service.
*/
#define MAX_SEND_RETRIES 10

/** Messages larger than 10 MB are dropped */
#define MAX_MESSAGE_SIZE_BYTES  10485760

#if 0
#include <glib/gprintf.h>
extern FILE *debug_print_file;
void debug_print(const char *format, ...);
#endif

#if 0
typedef enum {
    _LSTransportAddressTypeLocal,
    _LSTransportAddressTypeInet
} _LSTransportAddressType;

struct LSTransportAddressLocal {
    char *name;
};

typedef struct LSTransportAddressLocal _LSTransportAddressLocal;

struct LSTransportAddressInet {
    // TODO
};

typedef struct LSTransportAddressInet _LSTransportAddressInet;

struct LSTransportAddress {
    _LSTransportAddressType type;
    _LSTransportAddressLocal local;
    _LSTransportAddressInet inet;
};

typedef struct LSTransportAddress _LSTransportAddress;

_LSTransportAddress* _LSTransportAddressLocalNew(const char *name);
void _LSTransportAddressLocalFree(_LSTransportAddress *address);
bool _LSTransportSetupListener(_LSTransportAddress *address, _LSTransport *transport, LSError *lserror);
#endif

typedef enum LSTransportType {
    _LSTransportTypeInvalid = -1,
    _LSTransportTypeLocal,
    _LSTransportTypeInet
} _LSTransportType;

bool _LSTransportInit(_LSTransport **ret_transport, const char *service_name, LSTransportHandlers *handlers, LSError *lserror);
bool _LSTransportDisconnect(_LSTransport *transport, bool flush_and_send_shutdown);
void _LSTransportDeinit(_LSTransport *transport);
void _LSTransportGmainAttach(_LSTransport *transport, GMainContext *context);
GMainContext* _LSTransportGetGmainContext(const _LSTransport *transport);
bool _LSTransportGmainSetPriority(_LSTransport *transport, int priority, LSError *lserror);
bool _LSTransportConnect(_LSTransport *transport, bool local, bool public_bus, LSError *lserror);
bool _LSTransportAppendCategory(_LSTransport *transport, const char *category, LSMethod *methods, LSError *lserror);
_LSTransportConnectState _LSTransportConnectLocal(const char *unique_name, bool new_socket, int *fd, LSError *lserror);
bool _LSTransportListenLocal(const char *unique_name, mode_t mode, int *fd, LSError *lserror);
bool _LSTransportSetupListenerLocal(_LSTransport *transport, const char *name, mode_t mode, LSError *lserror);
bool _LSTransportSetupListenerInet(_LSTransport *transport, int port, LSError *lserror);
bool _LSTransportSendMessage(_LSTransportMessage *message, _LSTransportClient *client,
                        LSMessageToken *token, LSError *lserror);
void _LSTransportAddInitialWatches(_LSTransport *transport, GMainContext *context);
_LSTransportType _LSTransportGetTransportType(const _LSTransport *transport);
bool _LSTransportGetPrivileged(const _LSTransport *tansport);

inline bool _LSTransportIsHub(void);

bool LSTransportSend(_LSTransport *transport, const char *service_name, const char *category, const char *method, const char *payload, const char* applicationId, LSMessageToken *token, LSError *lserror);
bool _LSTransportSendReply(const _LSTransportMessage *message, const char *payload, LSError *lserror);

bool LSTransportCancelMethodCall(_LSTransport *transport, const char *service_name, LSMessageToken serial, LSError *lserror);

bool LSTransportPushRole(_LSTransport *transport, const char *path, LSError *lserror);

/* TODO: move these */
bool LSTransportSendMessageMonitorRequest(_LSTransport *transport, LSError *lserror);
bool _LSTransportSendMessageListClients(_LSTransport *transport, LSError *lserror);
bool _LSTransportSendMessageListServiceMethods(_LSTransport *transport, const char *service_name, LSError *lserror);
bool LSTransportSendQueryServiceStatus(_LSTransport *transport, const char *service_name, LSMessageToken *serial, LSError *lserror);
bool LSTransportSendQueryServiceCategory(_LSTransport *transport,
                                         const char *service_name, const char *category,
                                         LSMessageToken *serial, LSError *lserror);
const char* _LSTransportQueryNameReplyGetUniqueName(_LSTransportMessage *message);

#ifdef UNIT_TESTS
void _LSTransportSetTransportType(_LSTransport *transport, _LSTransportType type);
#endif // UNIT_TESTS

#endif // _TRANSPORT_H_
