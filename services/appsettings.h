//
// Copyright [2018] [Comcast NBCUniversal]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#ifndef __APP_SETTINGS_H__
#define __APP_SETTINGS_H__

#include "../defs.h"
#include "../rpcserver.h"

class AppSettingsService : public BasicRpcService
{
public:
  AppSettingsService();
  virtual ~AppSettingsService();
  virtual void init(std::string const& configFile,
    RpcNotificationFunction const& callback) override;
private:
  cJSON* get(cJSON const* req);
  cJSON* set(cJSON const* req);
};


/**
 * delete value
 * @param req the request include group and key
 * @param res the response
 */
int appSettings_delete(cJSON const* req, cJSON** res);
int appSettings_set(cJSON const* req, cJSON** res);
int appSettings_get(cJSON const* req, cJSON** res);


/**
 * read all current keys and values
 * @param req the request
 * @param res the response
 */
int appSettings_get_all(cJSON const* req, cJSON** res);


/**
 * add group
 * @param req the request
 * @param res the response
 */
int appSettings_add_group(cJSON const* req, cJSON** res);

/**
 * modify group, if group name is nullptr, all origin values will be put in default group
 * @param req the request include new group name
 * @param res the response
 */
int appSettings_modify_group(cJSON const* req, cJSON** res);

/**
 * delete group by name, the name is required
 * @param req the request include group name
 * @param res the response
 */
int appSettings_delete_group(cJSON const* req, cJSON** res);

/**
 * get ble values
 * @param key  the key
 * @return  the value
 */
char const* appSettings_get_ble_value(char const* key);

/**
 * get wifi values
 * @param key  the key
 * @return  the value
 */
char const* appSettings_get_wifi_value(char const* key);

#endif
