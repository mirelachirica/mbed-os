/*
 * Copyright (c) 2018, Arm Limited and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CONTROLPLANE_NETIF_H_
#define CONTROLPLANE_NETIF_H_

#include "nsapi_types.h"

namespace mbed {

// need to make this l3ip compatible
class ControlPlane_netif {
public:
    virtual nsapi_error_t send(const void *data, nsapi_size_t size) = 0;
    virtual nsapi_error_t recv(void *buffer, nsapi_size_t size) = 0;
    virtual void attach(void (*callback)(void *), void *data) = 0;
    virtual void data_received(char* buffer = 0, nsapi_size_t size = 0) = 0;
    int _cid;

    ControlPlane_netif();
    virtual ~ControlPlane_netif();
};

} // mbed namespace
#endif
