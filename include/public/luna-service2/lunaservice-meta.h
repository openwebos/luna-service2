/****************************************************************
 * @@@LICENSE
 *
 * Copyright (c) 2014 LG Electronics, Inc.
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
 * LICENSE@@@
 ****************************************************************/

/**
 *  @file lunaservice-meta.h
 */

#ifndef __LUNASERVICE_META_H
#define __LUNASERVICE_META_H

#include <pbnjson.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup LunaServiceMeta
 * @ingroup LunaService
 * @brief Luna Service meta-information manipulation
 */

/**
 * @addtogroup LunaServiceMeta
 * @{
 */

/**
 * Specify meta information about category
 *
 * Set JSON value that describes specified category. Provides validation schema
 * for input params and replies. Gives some description for calls etc.
 *
 * Note that some services with dynamically registered methods may wish to call
 *      this function after each LSRegisterCategoryAppend.
 *
 * @param sh  handle that identifies registered service on bus
 * @param category  identifier of category this information provided for
 * @param description  information itself (no ownership transfer)
 *                     @ref simpleBiffService.schema "see / category in example"
 * @param error  ouptut buffer for error description if applicable
 * @return  false in case of error
 */
bool LSCategorySetDescription(
	LSHandle *sh, const char *category,
	jvalue_ref description,
	LSError *error
);

/**
 * @example simpleBiffService.schema
 * Service description example
 */

/* TODO */

/* @} END OF LunaServiceMeta */

#ifdef __cplusplus
} // extern "C"
#endif

#endif
