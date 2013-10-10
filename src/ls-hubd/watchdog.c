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


#include <sys/time.h>
#include <string.h>
#include <stdlib.h>

#if 0
#if !(defined TARGET_DESKTOP)
#include "rdx.h"
#endif
#endif

#include "error.h"
#include "transport_utils.h"
#include "conf.h"
#include "watchdog.h"

#define WATCHDOG_FAILURE_MODE_STRING_NOOP   "noop"
#define WATCHDOG_FAILURE_MODE_STRING_CRASH  "crash"
#define WATCHDOG_FAILURE_MODE_STRING_RDX    "rdx"

#define WATCHDOG_TIMEOUT_OVERHEAD_SECS  2

#define WATCHDOG_RDX_COMPONENT  "ls-hubd.watchdog"
#define WATCHDOG_RDX_CAUSE      "Watchdog timer expired"
#define WATCHDOG_RDX_DETAIL     "Watchdog timeout"
#define WATCHDOG_RDX_TEXT       "Watchdog timeout"

#define WATCHDOG_RDX_REPORTER_CMD    "/bin/echo \"Watchdog timeout\" | /usr/sbin/rdx_reporter --component \"ls-hubd.watchdog\" --cause \"Watchdog timer expired\" --detail \"Watchdog timeout\" &"

static gint last_count_seen = 0;
static gint watchdog_count = 0;

#if !(defined TARGET_DESKTOP)
/* Can't use librdx because it creates a circular build dependency */
#if 0
static void
_WatchdogGenerateRdxReport(void)
{
    RdxReportMetadata md = create_rdx_report_metadata();
    rdx_report_metadata_set_component(md, WATCHDOG_RDX_COMPONENT);
    rdx_report_metadata_set_cause(md, WATCHDOG_RDX_CAUSE);
    rdx_report_metadata_set_detail(md, WATCHDOG_RDX_DETAIL);

    if (!rdx_make_report(md, WATCHDOG_RDX_TEXT))
    {
        LOG_LS_WARNING(MSGID_LSHUB_RDX_REPORT, 0, "Unable to make rdx report!");
    }
}
#endif

static void
_WatchdogGenerateRdxReport(void)
{
    LOG_LS_DEBUG("Generating RDX report");
    system(WATCHDOG_RDX_REPORTER_CMD);
}
#endif

/**
 *******************************************************************************
 * @brief SIGALRM handler to check whether the mainloop is still ticking.
 *
 * @param  signal   IN  signal received
 *******************************************************************************
 */
static void
_WatchdogSignalTimeout(int signal)
{
    gint cur_count = g_atomic_int_get(&watchdog_count);

    if (cur_count <= last_count_seen && cur_count != 0)
    {
        /* We're wedged -- take action */
        LOG_LS_WARNING(MSGID_LSHUB_WATCHDOG_ERR, 0, "Watchdog timeout after %d seconds", g_conf_watchdog_timeout_sec);
        switch (g_conf_watchdog_failure_mode)
        {
        case LSHubWatchdogFailureModeNoop:
            /* don't do anything */
            break;
        case LSHubWatchdogFailureModeCrash:
            LS_ASSERT(0);
            break;
        case LSHubWatchdogFailureModeRdx:
#if !(defined TARGET_DESKTOP)
            /* Generate rdx report. This isn't really safe because it's
             * most certainly calling non async-signal-safe functions (see
             * man 7 signal). The only way to get around that would be to make
             * this a separate thread. */
            _WatchdogGenerateRdxReport();
#else
            LOG_LS_WARNING(MSGID_LSHUB_WATCHDOG_ERR, 0,
                           "Watchdog failure mode set to \"%s\", "
                           "but this is not supported on the desktop. "
                           "Check the ls2 hub config file.",
                           WATCHDOG_FAILURE_MODE_STRING_RDX);
#endif
            break;
        case LSHubWatchdogFailureModeInvalid:
        default:
            LOG_LS_ERROR(MSGID_LSHUB_WATCHDOG_ERR, 0, "Unrecognized watchdog failure mode setting. Check ls2 hub config file");
            break;
        }
    }

    last_count_seen = cur_count;
}

/**
 *******************************************************************************
 * @brief Called from the mainloop after the timeout.
 *
 * @param  data
 *
 * @retval
 *******************************************************************************
 */
static gboolean
_WatchdogMainloopTimeout(gpointer data)
{
    g_atomic_int_inc(&watchdog_count);
    return TRUE;
}

/**
 *******************************************************************************
 * @brief Set a watchdog timer on the mainloop. The timeout is sepcified by the
 * configuration file.
 *
 * @param  lserror
 *
 * @retval
 *******************************************************************************
 */
bool
SetupWatchdog(LSError *lserror)
{
    if (g_conf_watchdog_failure_mode == LSHubWatchdogFailureModeNoop)
    {
        /* no-op mode chosen so don't set up the watchdog */
        return true;
    }

    /* add to default mainloop */
    if (g_conf_watchdog_timeout_sec < 5)
    {
        LOG_LS_WARNING(MSGID_LSHUB_WATCHDOG_ERR, 0, "Attempting to set watchdog timeout too low. Defaulting to 5 seconds");
        g_conf_watchdog_timeout_sec = 5;
    }

    g_timeout_add_seconds(g_conf_watchdog_timeout_sec - WATCHDOG_TIMEOUT_OVERHEAD_SECS, _WatchdogMainloopTimeout, NULL);

    struct itimerval itimer =
    {
        .it_interval =
        {
            .tv_sec = g_conf_watchdog_timeout_sec,
            .tv_usec = 0,
        },
        .it_value =
        {
            .tv_sec = g_conf_watchdog_timeout_sec,
            .tv_usec = 0,
        },
    };

    if (setitimer(ITIMER_REAL, &itimer, NULL) != 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LSHUB_TIMER_ERR, errno);
        return false;
    }

    _LSTransportSetupSignalHandler(SIGALRM, _WatchdogSignalTimeout);

    return true;
}


/**
 *******************************************************************************
 * @brief Convert a failure mode string to a numeric type.
 *
 * @param  mode_str     IN  failure mode string ("rdx", "noop", "crash", etc)
 *
 * @retval  failure mode type
 *******************************************************************************
 */
LSHubWatchdogFailureMode
LSHubWatchdogProcessFailureMode(const char *mode_str)
{
    if (strcmp(mode_str, WATCHDOG_FAILURE_MODE_STRING_NOOP) == 0)
    {
        return LSHubWatchdogFailureModeNoop;
    }
    else if (strcmp(mode_str, WATCHDOG_FAILURE_MODE_STRING_CRASH) == 0)
    {
        return LSHubWatchdogFailureModeCrash;
    }
    else if (strcmp(mode_str, WATCHDOG_FAILURE_MODE_STRING_RDX) == 0)
    {
        return LSHubWatchdogFailureModeRdx;
    }
    else
    {
        return LSHubWatchdogFailureModeInvalid;
    }
}
