#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <unistd.h>
#include "../security.h"
#include "../conf.h"
#include "../hub.h"

const char* steady_roles[] = {TEST_STEADY_ROLES_DIRECTORY, NULL};
const char* steady_services[] = {TEST_STEADY_SERVICES_DIRECTORY, NULL};
const char* volatile_roles[] = {TEST_VOLATILE_ROLES_DIRECTORY, NULL};
const char* volatile_services[] = {TEST_VOLATILE_SERVICES_DIRECTORY, NULL};

static void test_LSHubScanServiceDirectories(void *fixture, gconstpointer user_data)
{
    LSError lserror;
    LSErrorInit(&lserror);

    // load services from steady directories
    g_assert(ConfigKeyProcessDynamicServiceDirs(steady_services, GINT_TO_POINTER(STEADY_DIRS), &lserror));

    g_assert(ServiceMapLookup("steady.service1") != NULL);
    g_assert(ServiceMapLookup("steady.service2") != NULL);
    g_assert(ServiceMapLookup("steady.service3_") != NULL);
    g_assert(ServiceMapLookup("steady.service4_") != NULL);
    g_assert(ServiceMapLookup("volatile.service1") == NULL);
    g_assert(ServiceMapLookup("volatile.service2") == NULL);
    g_assert(ServiceMapLookup("volatile.service3_") == NULL);
    g_assert(ServiceMapLookup("volatile.service4_") == NULL);

    // load services from volatile directories
    g_assert(ConfigKeyProcessDynamicServiceDirs(volatile_services, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));

    g_assert(ServiceMapLookup("steady.service1") != NULL);
    g_assert(ServiceMapLookup("steady.service2") != NULL);
    g_assert(ServiceMapLookup("steady.service3_") != NULL);
    g_assert(ServiceMapLookup("steady.service4_") != NULL);
    g_assert(ServiceMapLookup("volatile.service1") != NULL);
    g_assert(ServiceMapLookup("volatile.service2") != NULL);
    g_assert(ServiceMapLookup("volatile.service3_") != NULL);
    g_assert(ServiceMapLookup("volatile.service4_") != NULL);

    // remove services from steady dirs
    g_assert(ServiceInitMap(&lserror, false));
    g_assert(ServiceMapLookup("steady.service1") == NULL);
    g_assert(ServiceMapLookup("steady.service2") == NULL);
    g_assert(ServiceMapLookup("steady.service3_") == NULL);
    g_assert(ServiceMapLookup("steady.service4_") == NULL);
    g_assert(ServiceMapLookup("volatile.service1") != NULL);
    g_assert(ServiceMapLookup("volatile.service2") != NULL);
    g_assert(ServiceMapLookup("volatile.service3_") != NULL);
    g_assert(ServiceMapLookup("volatile.service4_") != NULL);

    // remove services from volatile dirs
    g_assert(ServiceInitMap(&lserror, true));
    g_assert(ServiceMapLookup("steady.service1") == NULL);
    g_assert(ServiceMapLookup("steady.service2") == NULL);
    g_assert(ServiceMapLookup("steady.service3_") == NULL);
    g_assert(ServiceMapLookup("steady.service4_") == NULL);
    g_assert(ServiceMapLookup("volatile.service1") == NULL);
    g_assert(ServiceMapLookup("volatile.service2") == NULL);
    g_assert(ServiceMapLookup("volatile.service3_") == NULL);
    g_assert(ServiceMapLookup("volatile.service4_") == NULL);
}

static void test_LSHubScanRolesDirectories(void *fixture, gconstpointer user_data)
{
    LSError lserror;
    LSErrorInit(&lserror);

    // scan roles from steady directories
    g_assert(ProcessRoleDirectories(steady_roles, GINT_TO_POINTER(STEADY_DIRS), &lserror));
    g_assert(ProcessRoleDirectories(steady_roles, GINT_TO_POINTER(STEADY_DIRS), &lserror));

    g_assert(LSHubRoleMapLookup("/bin/foo") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/foo1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/bar") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app2") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app2") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app3") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app4") == NULL);

    g_assert(LSHubPermissionMapLookup("com.webos.foo") != NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.foo1") != NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.bar1") != NULL);
    g_assert(LSHubPermissionMapLookup("steady.app1") != NULL);
    g_assert(LSHubPermissionMapLookup("steady.app2") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app1") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app2") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app3") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app4") == NULL);

    // scan roles from steady directories
    g_assert(ProcessRoleDirectories(volatile_roles, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));
    g_assert(ProcessRoleDirectories(volatile_roles, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));

    g_assert(LSHubRoleMapLookup("/bin/foo") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/foo1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/bar") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app2") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app2") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app3") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app4") != NULL);

    g_assert(LSHubPermissionMapLookup("com.webos.foo") != NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.foo1") != NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.bar1") != NULL);
    g_assert(LSHubPermissionMapLookup("steady.app1") != NULL);
    g_assert(LSHubPermissionMapLookup("steady.app2") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app1") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app2") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app3") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app4") != NULL);

    // reset roles from steady dirs
    g_assert(PermissionsAndRolesInit(&lserror, false));

    g_assert(LSHubRoleMapLookup("/bin/foo") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/foo1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/bar") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app2") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app1") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app2") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app3") != NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app4") != NULL);

    g_assert(LSHubPermissionMapLookup("com.webos.foo") == NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.foo1") == NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.bar1") == NULL);
    g_assert(LSHubPermissionMapLookup("steady.app1") == NULL);
    g_assert(LSHubPermissionMapLookup("steady.app2") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app1") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app2") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app3") != NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app4") != NULL);

    // reset roles from volatile dirs
    g_assert(PermissionsAndRolesInit(&lserror, true));

    g_assert(LSHubRoleMapLookup("/bin/foo") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/foo1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/bar") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/steady.app2") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app1") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app2") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app3") == NULL);
    g_assert(LSHubRoleMapLookup("/bin/volatile.app4") == NULL);

    g_assert(LSHubPermissionMapLookup("com.webos.foo") == NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.foo1") == NULL);
    g_assert(LSHubPermissionMapLookup("com.webos.bar1") == NULL);
    g_assert(LSHubPermissionMapLookup("steady.app1") == NULL);
    g_assert(LSHubPermissionMapLookup("steady.app2") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app1") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app2") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app3") == NULL);
    g_assert(LSHubPermissionMapLookup("volatile.app4") == NULL);
}

static void test_NULLcheck(void *fixture, gconstpointer user_data)
{
    LSError lserror;
    LSErrorInit(&lserror);

    g_assert(ConfigKeyProcessDynamicServiceDirs(NULL, GINT_TO_POINTER(STEADY_DIRS), &lserror));
    g_assert(ConfigKeyProcessDynamicServiceDirs(NULL, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));
    g_assert(ConfigKeyProcessDynamicServiceDirs(NULL, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));
    const char* dirs[] = {NULL};
    g_assert(ConfigKeyProcessDynamicServiceDirs(dirs, GINT_TO_POINTER(STEADY_DIRS), &lserror));
    g_assert(ConfigKeyProcessDynamicServiceDirs(dirs, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));
    g_assert(ConfigKeyProcessDynamicServiceDirs(dirs, GINT_TO_POINTER(VOLATILE_DIRS), &lserror));
}

int main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaServiceHub", G_LOG_LEVEL_ERROR);

    ConfigSetDefaults();

    g_test_add("/hub/LSHubScanServiceDirectories", void, NULL, NULL, test_LSHubScanServiceDirectories, NULL);
    g_test_add("/hub/LSHubScanRolesDirectories", void, NULL, NULL, test_LSHubScanRolesDirectories, NULL);
    g_test_add("/hub/NULLcheck", void, NULL, NULL, test_NULLcheck, NULL);

    return g_test_run();
}
