
/** \addtogroup netsocket */
/** @{*/
/* Socket
 * Copyright (c) 2015 ARM Limited
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

#ifndef CELLULARNONIPSOCKET_H
#define CELLULARNONIPSOCKET_H

#include "netsocket/Socket.h"
#include "rtos/Mutex.h"
#include "rtos/EventFlags.h"
#include "Callback.h"
#include "mbed_toolchain.h"
#include "ControlPlane_netif.h"
#include "CellularContext.h"

namespace mbed {

//Socket implementation for non ip datagrams over cellular control plane
class CellularNonIPSocket : public Socket {
public:
    /** Destroy the socket.
     *
     *  @note Closes socket if it's still open.
     */
    virtual ~CellularNonIPSocket();

    //Create and open a socket on the given cellular context
   CellularNonIPSocket(CellularContext *cellular_context);

    //Cellular context that has support for providing a control plane netif / get_cp_netif()
    nsapi_error_t open(CellularContext *iface);

    nsapi_error_t open(ControlPlane_netif *cp_netif);

    nsapi_error_t close();

    nsapi_size_or_error_t send(const void *data, nsapi_size_t size);

    nsapi_size_or_error_t recv(void *data, nsapi_size_t size);

    void set_blocking(bool blocking);

    void set_timeout(int timeout);

    void sigio(mbed::Callback<void()> func);

    // NOT SUPPORTED
    nsapi_error_t connect(const SocketAddress &address);
    Socket *accept(nsapi_error_t *error = NULL);
    nsapi_error_t listen(int backlog = 1);

#if !defined(DOXYGEN_ONLY)

protected:
    CellularNonIPSocket();
    virtual void event();

    uint32_t _timeout;
    mbed::Callback<void()> _event;
    mbed::Callback<void()> _callback;
    rtos::EventFlags _event_flag;
    rtos::Mutex _lock;
    uint8_t _readers;
    uint8_t _writers;
    volatile unsigned _pending;
    bool _factory_allocated;

    // Event flags
    static const int READ_FLAG     = 0x1u;
    static const int WRITE_FLAG    = 0x2u;
    static const int FINISHED_FLAG = 0x3u;

    ControlPlane_netif *_cp_netif;
    bool _opened;

#endif //!defined(DOXYGEN_ONLY)
};

} // namespace mbed

#endif // CELLULARNONIPSOCKET_H

/** @}*/
