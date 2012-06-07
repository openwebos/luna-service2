/* @@@LICENSE
*
*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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


#include <syslog.h>
#include <glib.h>
#include "log.h"

#include <PmLogLib/PmLogLib.h>
static PmLogContext hub_log_context;

static int
_GlibToSyslogLevel(int glib_level)
{
    switch (glib_level & G_LOG_LEVEL_MASK)
    {
    case G_LOG_LEVEL_ERROR:
        return LOG_CRIT;
    case G_LOG_LEVEL_CRITICAL:
        return LOG_ERR;
    case G_LOG_LEVEL_WARNING:
        return LOG_WARNING;
    case G_LOG_LEVEL_MESSAGE:
        return LOG_NOTICE;
    case G_LOG_LEVEL_INFO:
        return LOG_INFO;
    case G_LOG_LEVEL_DEBUG:
        return LOG_DEBUG;
    }
    
    return LOG_NOTICE;
}

static int
_GlibToPmlogLevel(int glib_level)
{
    switch (glib_level & G_LOG_LEVEL_MASK)
    {
    case G_LOG_LEVEL_ERROR: 
        return kPmLogLevel_Alert;
    case G_LOG_LEVEL_CRITICAL: 
        return kPmLogLevel_Critical;
    case G_LOG_LEVEL_WARNING: 
        return kPmLogLevel_Warning;
    case G_LOG_LEVEL_MESSAGE: 
        return kPmLogLevel_Notice;
    case G_LOG_LEVEL_INFO: 
        return kPmLogLevel_Info;
    case G_LOG_LEVEL_DEBUG: 
        return kPmLogLevel_Debug;
    }

    return kPmLogLevel_None;
}

static void
_PmLogLibFunc(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
    PmLogPrint(hub_log_context, _GlibToPmlogLevel(log_level), "%s", message);
}

void
SetLoggingPmLogLib(bool public_hub)
{
    if (public_hub)
    {
        PmLogGetContext(HUB_PUBLIC_LOG_CONTEXT, &hub_log_context);
    }
    else
    {
        PmLogGetContext(HUB_PRIVATE_LOG_CONTEXT, &hub_log_context);
    }

    g_log_set_default_handler(_PmLogLibFunc, NULL);
}

static void
_SyslogLogFunc(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
    syslog(LOG_USER | _GlibToSyslogLevel(log_level), "%s", message);
}

void
SetLoggingSyslog(void)
{
    g_log_set_default_handler(_SyslogLogFunc, NULL);
}
