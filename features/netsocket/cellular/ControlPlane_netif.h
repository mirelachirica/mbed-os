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

/* Length of the buffer storing data received over control plane */
#define MAX_CP_DATA_RECV_LEN 512

// need to make this l3ip compatible
class ControlPlane_netif {
public:
    ControlPlane_netif() {}
    virtual ~ControlPlane_netif() {}

    /** Send data over control plane
    *
    *  @param cpdata            Buffer of data to be sent over control plane connection
    *  @param cpdata_length     Length of data in bytes
    *  @return                  Number of sent bytes on success, negative error
    *                           code on failure.
    */
    virtual nsapi_size_or_error_t send(const void *cpdata, nsapi_size_t cpdata_length) = 0;

    /** Receive data over control plane
    *
    *  @param cpdata            Destination buffer for data received from control plane connection
    *  @param cpdata_length     Length of data in bytes
    *  @return                  Number of received bytes on success, negative error
    *                           code on failure.
    */
    virtual nsapi_size_or_error_t recv(void *cpdata, nsapi_size_t cpdata_length) = 0;

    /** Register a callback on state change of the socket
    *
    *  The specified callback will be called on state changes such as when
    *  the socket can recv/send/accept successfully and on when an error
    *  occurs. The callback may also be called spuriously without reason.
    *
    *  The callback may be called in an interrupt context and should not
    *  perform expensive operations such as recv/send calls.
    *
    *  @param callback     Function to call on state change
    *  @param data         Argument to pass to callback
    */
    virtual void attach(void (*callback)(void *), void *data) = 0;

    /** Receives data from the control plane PDP context
    *
    *  This function is called by cellular PDP context when data
    *  is received from network. It will set the receiving buffer,
    *  its length and also invoke the callback set by the above attach.
    *
    *  @param buffer     Buffer containing received data
    *  @param size       Size of data in bytes
    */
    virtual void data_received(char* buffer = 0, nsapi_size_t size = 0) = 0;
};

} // mbed namespace
#endif
