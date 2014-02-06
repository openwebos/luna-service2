/* @@@LICENSE
*
*      Copyright (c) 2010-2014 LG Electronics, Inc.
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

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include "transport_shm.h"

#define SHM_NAME_PUB    "/ls2.monitor.pub.shm"
#define SHM_NAME_PRV    "/ls2.monitor.priv.shm"

#define SHM_MODE      0666

#define FENCE_VAL       0xdeadbeef

struct _LSTransportShmData
{
    uint32_t front_fence;
    pthread_mutex_t lock;
    _LSTransportMonitorSerial serial;
    uint32_t back_fence;
};

typedef struct _LSTransportShmData _LSTransportShmData;

struct _LSTransportShm
{
    _LSTransportShmData* data;
};

/** protects singleton mapping initialization from multiple threads */
static pthread_mutex_t shm_map_lock = PTHREAD_MUTEX_INITIALIZER;

static _LSTransportShmData *shm_map_addr_pub = NULL;   /**< singleton mapping of
                                                         the shared memory
                                                         region for the process */

static _LSTransportShmData *shm_map_addr_prv = NULL;   /**< singleton mapping of
                                                         shared memory region for
                                                         process */

static _LSTransportShmData*
_LSTransportShmInitOnce(bool public_bus, LSError *lserror)
{
    bool shm_needs_init = true;
    const char *shm_name = NULL;
    _LSTransportShmData *map = NULL;
    int fd = -1;
    int ret = 0;

    if (public_bus)
    {
        shm_name = SHM_NAME_PUB;
    }
    else
    {
        shm_name = SHM_NAME_PRV;
    }

    pthread_mutex_lock(&shm_map_lock);

    if (public_bus)
    {
        map = shm_map_addr_pub;
    }
    else
    {
        map = shm_map_addr_prv;
    }

    if (map)
    {
        /* we've already mapped in the shared memory for this process */
        goto unlock;
    }

    fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, SHM_MODE);

    if (fd == -1)
    {
        /* Another process already created it, so we just use the existing one */
        if (errno == EEXIST)
        {
            shm_needs_init = false;

            fd = shm_open(shm_name, O_RDWR, SHM_MODE);

            if (fd == -1)
            {
                _LSErrorSetFromErrno(lserror, MSGID_LS_SHARED_MEMORY_ERR, errno);
                goto error;
            }
        }
        else
        {
            _LSErrorSetFromErrno(lserror, MSGID_LS_SHARED_MEMORY_ERR, errno);
            goto error;
        }
    }
    else
    {
        /* NOV-117816: Make sure the mode is correctly set */
        fchmod(fd, SHM_MODE);
    }

    if (shm_needs_init)
    {
        ret = ftruncate(fd, sizeof(_LSTransportShmData));

        if (ret == -1)
        {
            _LSErrorSetFromErrno(lserror, MSGID_LS_SHARED_MEMORY_ERR, errno);
            goto error;
        }
    }

    map = mmap(NULL, sizeof(_LSTransportShmData), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (map == MAP_FAILED)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_SHARED_MEMORY_ERR, errno);
        goto error;
    }

    /* lock the page so it's not swapped out -- passing the MAP_LOCKED
     * flag to mmap works on Linux, but not Mac */
    ret = mlock(map, sizeof(_LSTransportShmData));

    if (ret == -1)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_SHARED_MEMORY_ERR, errno);
        goto error;
    }

    if (shm_needs_init)
    {
        pthread_mutexattr_t attr;

        /* mark mutex as being shared by multiple processes */
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

        if (pthread_mutex_init(&map->lock, &attr))
        {
            LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex.");
            goto error;
        }
        map->serial = MONITOR_SERIAL_INVALID;
        map->front_fence = FENCE_VAL;
        map->back_fence = FENCE_VAL;
    }

    /* success, so save the resulting mappping */
    if (public_bus)
    {
        shm_map_addr_pub = map;
    }
    else
    {
        shm_map_addr_prv = map;
    }

unlock:
    pthread_mutex_unlock(&shm_map_lock);

    /* closing the fd is ok since we've already mmap'ed in the memory
     * see man shm_open for more details */
    if (fd != -1) close(fd);
    return map;

error:
    pthread_mutex_unlock(&shm_map_lock);
    if (fd != -1) close(fd);
    return MAP_FAILED;
}

bool
_LSTransportShmInit(_LSTransportShm** shm, bool public_bus, LSError* lserror)
{
    _LSTransportShm* ret_shm = g_new0(_LSTransportShm, 1);

    ret_shm->data = _LSTransportShmInitOnce(public_bus, lserror);

    if (ret_shm->data == MAP_FAILED)
    {
        goto error;
    }

    *shm = ret_shm;

    return true;

error:
    g_free(ret_shm);
    return false;
}

_LSTransportMonitorSerial
_LSTransportShmGetSerial(_LSTransportShm* shm)
{
    LS_ASSERT(shm != NULL);

    _LSTransportMonitorSerial ret = MONITOR_SERIAL_INVALID;

    /* Make sure a rogue process didn't mess with the shared mem */
    if (shm->data->front_fence == FENCE_VAL &&
        shm->data->back_fence == FENCE_VAL)
    {
        pthread_mutex_lock(&shm->data->lock);
        ret = ++shm->data->serial;

        if (unlikely(ret == MONITOR_SERIAL_INVALID))
        {
            ret++;
        }
        pthread_mutex_unlock(&shm->data->lock);
    }

    return ret;
}

void
_LSTransportShmDeinit(_LSTransportShm** shm)
{
    /* Don't worry about unmapping, since everyone who uses the library
     * uses it for the lifetime of their process. Otherwise, we need to
     * refcount the singleton mapping and unmap it on the last use */

    g_free((*shm));
    *shm = NULL;
}
