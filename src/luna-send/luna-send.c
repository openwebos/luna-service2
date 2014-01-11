/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
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

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <cjson/json.h>
#include <luna-service2/lunaservice.h>

#if (defined(__APPLE__) && defined(__MACH__)) || defined(WIN32)
#	include <clock_gettime_implementation.h>
#endif

static int sLogLevel = G_LOG_LEVEL_MESSAGE;

static int count = -1;
static double roundtripTime = 0.0;
static struct timespec startTime, stopTime;
static int roundtripCount = 0;
static int sentBytes = 0;
static int rcvdBytes = 0;
static bool line_number = false;
static bool format_response = false;
static int current_line_number = 0;
static GList * query_list = NULL;

static gchar *url = NULL;
static gchar *message = NULL;
static gchar *appId = NULL;

static gboolean
goodbye (gpointer data)
{
    GMainLoop *loop = (GMainLoop*)data;
    g_main_loop_quit (loop);
    return FALSE;
}

#define INDENT_INCREMENT 4
static void
pretty_print(struct json_object * object, int first_indent, int indent)
{
	if (!object) {
        printf("%*s<NULL>", first_indent, "");
		return;
	}

    switch (json_object_get_type(object)) {
    case json_type_null:
    case json_type_boolean:
    case json_type_int:
    case json_type_double:
    case json_type_string:
        printf("%*s%s", first_indent, "", json_object_to_json_string(object));
        break;
    case json_type_array:
    {
        int len = json_object_array_length(object);
        int i;
        printf("%*s[", first_indent, "");
        bool first = true;
        for (i=0;i<len;i++) {
          if (first) {
            printf("\n");
            first = false;
          } else {
            printf(",\n");
          }
          pretty_print(json_object_array_get_idx(object, i), indent + INDENT_INCREMENT, indent + INDENT_INCREMENT);
        }
        printf("\n%*s]", indent, "");
        break;
    }
    case json_type_object:
    {
        printf("%*s{", first_indent, "");
        bool first = true;
        struct json_object_iterator it = json_object_iter_begin(object);
        struct json_object_iterator itEnd = json_object_iter_end(object);
        while (!json_object_iter_equal(&it, &itEnd)) {
          if (first) {
            printf("\n");
            first = false;
          } else {
            printf(",\n");
          }
          // FIXME: contents of key are not being escaped
          printf("%*s\"%s\": ", indent+INDENT_INCREMENT, "", json_object_iter_peek_name(&it));
          pretty_print(json_object_iter_peek_value(&it), 0, indent + INDENT_INCREMENT);
          json_object_iter_next(&it);
        }
        printf("\n%*s}", indent, "");
        break;
    }
	default:
        printf("%*s<unknown cjson type %d>", first_indent, "", json_object_get_type(object));
		break;
    }
}

// Apply JSON query, of a.b.c, or a.b[2].c[3][4], returning a refcount-incremented reference
// to the sub-object which matches the query, or NULL.
struct json_object * apply_query(struct json_object * obj, char * query)
{
  char * pos = query;
  while (obj != NULL && pos != NULL && pos[0] != '\0') {
    if (pos[0] == '[') {
      char * sep = strchr(pos, ']');
      if (!sep || sep == pos+1)
        return NULL;
      char * end = NULL;
      int val = strtol(pos+1, &end, 10);
      if (val < 0)
        return NULL;
      if (end != sep)
        return NULL;
      if (obj && json_object_is_type(obj, json_type_array))
        obj = json_object_array_get_idx(obj, val);
      else
        return NULL;
      pos = sep+1;
    } else if (pos[0] == '.' || pos == query) { // dots must proceed key lookup, except at beginning of query
      if (pos != query)
        pos++; // skip past dot
      size_t len = strcspn(pos, "[.");
      char orig = pos[len];
      pos[len] = '\0';
      if (obj && json_object_is_type(obj, json_type_object))
        obj = json_object_object_get(obj, pos);
      else
        return NULL;
      pos[len] = orig;
      pos += len;
    } else
      return NULL; // not sure how we got here
  }

  if (obj) {
    // increment refcount of result, so it can be added to the new object
    return json_object_get(obj);
  } else {
    return NULL;
  }
}

static bool
serviceResponse(LSHandle *sh, LSMessage *reply, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);
    LSMessageToken token;

    const char *payload;
    bool free_payload = false;

    token = LSMessageGetResponseToken(reply);
    payload = LSMessageGetPayload(reply);

    //g_message("%s Handling: %ld, %s", __FUNCTION__, token, payload);

    if (line_number) {
      printf("%2d: ", current_line_number++);
    }

    if (query_list != NULL) {
      // Use set of queries to transform original object into reduced form that
      // only contains queried selections -- then pass that through normal formatting.
      struct json_object *original = json_tokener_parse(payload);
      struct json_object *new_object = json_object_new_object();
      GList * query = query_list;
      if ( original && !is_error(original) ) {
        while (query) {
          char * query_text = (char*)query->data;
          struct json_object * result = apply_query(original, query_text);
          json_object_object_add(new_object, query_text, result);
          query = query->next;
        }
        payload = strdup(json_object_get_string(new_object));
        free_payload = true;
        json_object_put(new_object);
      }
    }

    if (format_response) {
      struct json_object *object = json_tokener_parse(payload);
      if ( !object || is_error(object) ) {
        // fall back to plain print
        printf("%s\n", payload);
      } else {
        pretty_print(object, 0, line_number ? 4 /* expected characters in line numbers */ : 0);
        printf("\n");
        json_object_put(object);
      }
    } else {
      printf("%s\n", payload);
    }

    if (free_payload)
      free((void*)payload);

    fflush(stdout);

    if (--count == 0)
    {
        bool retVal = LSCallCancel (sh, token, &lserror);
        if (!retVal)
        {
            LSErrorPrint (&lserror, stderr);
            LSErrorFree (&lserror);
        }
        g_timeout_add (300, goodbye, ctx);
        return true;
    }

    return true;
}

static bool
timingServiceResponse(LSHandle *sh, LSMessage *reply, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);
    LSMessageToken token;

    const char *payload;

    clock_gettime(CLOCK_MONOTONIC, &stopTime);

    token = LSMessageGetResponseToken(reply);
    payload = LSMessageGetPayload(reply);

    double duration = ((double)stopTime.tv_sec + (((double)stopTime.tv_nsec)/1000000000.0)) -
                     ((double)startTime.tv_sec + (((double)startTime.tv_nsec)/1000000000.0));

    roundtripTime += duration;
    roundtripCount++;
    rcvdBytes += strlen(payload);
    sentBytes += url ? strlen(url) : 0;
    sentBytes += message ? strlen(message) : 0;

    g_message("%s Got response: duration %.02f ms, token %ld, payload %s", __FUNCTION__, duration * 1000.0, token, payload);

    if (--count > 0)
    {
        // resend the message!
        LSMessageToken sessionToken;

        clock_gettime(CLOCK_MONOTONIC, &startTime);

        /* Basic sending */
        bool retVal = LSCallFromApplication(sh, url, message, appId,
                     timingServiceResponse, ctx, &sessionToken, &lserror);
        if (!retVal)
        {
            LSErrorPrint (&lserror, stderr);
            LSErrorFree (&lserror);
        }
    } else {
        bool retVal = LSCallCancel (sh, token, &lserror);
        if (!retVal)
        {
            LSErrorPrint (&lserror, stderr);
            LSErrorFree (&lserror);
        }
        g_timeout_add (300, goodbye, ctx);
        return true;
    }

    return true;
}

void
PrintUsage(const char* progname)
{
    printf("%s uri message\n", progname);
    printf(" -h this help screen\n"
#ifndef PUBLIC_HUB_ONLY
           " -P send over the public bus (send over private bus is default)\n"
#endif // PUBLIC_HUB_ONLY
           " -s send a signal\n"
           " -a send specified appId in message (default is none)\n"
           " -m service name (default is none)\n"
           " -d turn debug logging on\n"
           " -i turn on interactive mode\n"
           " -t x average over x times getting one response\n"
           " -n x exit interactive mode after x replies\n"
           " -l number responses\n"
           " -f format JSON responses usefully\n"
           " -q apply specific query to responses (multiple queries may be supplied), e.g.:\n"
           "        -q 'returnValue' -q 'queues[0]'\n");
}

void
g_log_filter(const gchar *log_domain,
    GLogLevelFlags log_level,
        const gchar *message,
        gpointer unused_data)
{
    if (log_level > sLogLevel) return;

    g_log_default_handler(log_domain, log_level, message, unused_data);
}


static gboolean
input_closed(GIOChannel *source, GIOCondition condition, gpointer data)
{
    /* Only get this callback if we hit an error or hangup condition */
    g_main_loop_quit((GMainLoop *)data);
    return TRUE;
}


int
main(int argc, char **argv)
{
    bool interactive = false;
    bool timing = false;
    bool signal = false;
    bool use_public_bus =
#ifdef PUBLIC_HUB_ONLY
        true;
#else
        false;
#endif // PUBLIC_HUB_ONLY
    char *serviceName = NULL;
    int optionCount = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hdisrlfn:t:m:a:q:"
#ifndef PUBLIC_HUB_ONLY
                                     "P"
#endif // PUBLIC_HUB_ONLY
                         )) != -1)
    {
    switch (opt) {
    case 'i':
        interactive = true;
        optionCount++;
        break;
    case 's':
        signal = true;
        optionCount++;
        break;
#ifndef PUBLIC_HUB_ONLY
    case 'P':
        use_public_bus = true;
        optionCount++;
        break;
#endif // PUBLIC_HUB_ONLY
    case 'd':
        sLogLevel = G_LOG_LEVEL_DEBUG;
        optionCount++;
        break;
    case 'n':
        interactive = true;
        count = atoi(optarg);
        optionCount+=2;
        break;
    case 't':
        timing = true;
        count = atoi(optarg);
        optionCount+=2;
        break;
    case 'm':
        serviceName = g_strdup(optarg);
        optionCount+=2;
        break;
    case 'a':
        appId = g_strdup(optarg);
        optionCount+=2;
        break;
    case 'l':
        line_number = true;
        optionCount++;
        break;
    case 'f':
        format_response = true;
        optionCount++;
        break;
    case 'q':
        query_list = g_list_append(query_list, g_strdup(optarg));
        optionCount+=2;
        break;
    case 'h':
    default:
        PrintUsage(argv[0]);
        return 0;
        }
    }

    if (argc < 3 + optionCount) {
        PrintUsage(argv[0]);
        return 0;
    }

    g_log_set_default_handler(g_log_filter, NULL);

    GMainLoop *mainLoop = g_main_loop_new(NULL, FALSE);

    if (mainLoop == NULL)
    {
        g_critical("Unable to create mainloop");
        exit(EXIT_FAILURE);
    }

    LSError lserror;
    LSErrorInit(&lserror);

    LSHandle *sh = NULL;
    bool serviceInit = LSRegisterPubPriv(serviceName, &sh,
                use_public_bus, &lserror);

    if (!serviceInit) goto exit;

    bool gmainAttach = LSGmainAttach(sh, mainLoop, &lserror);
    if (!gmainAttach) goto exit;

    url = g_strdup(argv[optionCount + 1]);
    message = g_strdup(argv[optionCount + 2]);

    LSMessageToken sessionToken;
    bool retVal;

    if (timing) {

      /* Timing loop */
      clock_gettime(CLOCK_MONOTONIC, &startTime);
      retVal = LSCallFromApplication(sh, url, message, appId,
            timingServiceResponse, mainLoop, &sessionToken, &lserror);

      if (!retVal) goto exit;

      g_main_loop_run(mainLoop);

      printf("Total time %.02f ms, %d iterations, %.02f ms per iteration\n",
        roundtripTime * 1000.0, roundtripCount, (roundtripTime / roundtripCount) * 1000.0);

      printf("%d bytes sent, %d bytes received\n",
        sentBytes, rcvdBytes);

    } else {

      if (signal)
      {
          retVal = LSSignalSend(sh, url, message, &lserror);
      }
      else
      {
          /* Basic sending */
          retVal = LSCallFromApplication(sh, url, message, appId,
                serviceResponse, mainLoop, &sessionToken, &lserror);
      }

      if (!retVal) goto exit;

      if (interactive && !signal)
      {
          g_io_add_watch(g_io_channel_unix_new(0), G_IO_ERR|G_IO_HUP, input_closed, mainLoop);
          g_main_loop_run(mainLoop);
      }
      else if (!signal)
      {
          /*
           * NOV-93580: In the non-interactive case, we can't guarantee that
           * an LSCall() will necessarily get the QueryNameReply before
           * shutting down if it does not wait for (or have) a reply from the
           * far side.
           */
          g_critical("WARNING: you must always call luna-send with \"-i\" or \"-n\". Exiting with failure return code.");
          exit(EXIT_FAILURE);
      }
    }

exit:

    if (LSErrorIsSet(&lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    if (sh != NULL)
    {
        if (!LSUnregister(sh, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
    }

    g_main_loop_unref(mainLoop);

    if (url)
        g_free (url);

    if (message)
        g_free (message);

    return 0;
}
