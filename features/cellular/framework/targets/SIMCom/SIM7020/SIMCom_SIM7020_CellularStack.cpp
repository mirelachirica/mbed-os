/*
 * Copyright (c) 2019, Arm Limited and affiliates.
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

#include "SIMCom_SIM7020_CellularStack.h"
#include "CellularLog.h"
#include "CellularUtil.h"
#include "stdlib.h"

#define MAX_SOCKET    5
#define MAX_SEND_SIZE 512

using namespace mbed;

uint8_t SIMCom_SIM7020_CellularStack::_rx_buffer[] = {0};
SIMCom_SIM7020_CellularStack::SIMCom_SIM7020_CellularStack(ATHandler       &atHandler,
                                                           int              cid,
                                                           nsapi_ip_stack_t stack_type) :
                                                           AT_CellularStack(atHandler, cid, stack_type)
{
    _at.set_urc_handler("+CSONMI:",
                        mbed::Callback<void()>(this, &SIMCom_SIM7020_CellularStack::urc_csonmi));
    _at.set_urc_handler("+CSOERR:",
                        mbed::Callback<void()>(this, &SIMCom_SIM7020_CellularStack::urc_socket_closed));
}

SIMCom_SIM7020_CellularStack::~SIMCom_SIM7020_CellularStack()
{
    _at.set_urc_handler("+CSONMI:", NULL);
    _at.set_urc_handler("+CSOERR:", NULL);
}

nsapi_error_t SIMCom_SIM7020_CellularStack::socket_listen(nsapi_socket_t handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t SIMCom_SIM7020_CellularStack::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t SIMCom_SIM7020_CellularStack::socket_connect(nsapi_socket_t handle, const SocketAddress &address)
{
    CellularSocket *socket = static_cast<CellularSocket *>(handle);

    if (socket != NULL) {
        if (!socket->created) {
            _at.lock();
            const nsapi_error_t err = create_socket_impl(socket);
            _at.unlock();
            if (err != NSAPI_ERROR_OK) {
                return err;
            }
        }
    } else {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    _at.lock();
	_at.cmd_start("AT+CSOCON=");
    _at.write_int(socket->id);
    _at.write_int(address.get_port());
    _at.write_string(address.get_ip_address());
#if 0
    _at.cmd_stop();
    _at.cmd_stop_read_resp();
#endif
    _at.cmd_stop_read_resp();
#if 0
                _at.cmd_stop();

                _at.resp_start("+CSOCON:");
                _at.resp_stop();
#endif
    _at.unlock();

    if (_at.get_last_error() == NSAPI_ERROR_OK) {
        socket->remoteAddress = address;
        socket->connected 	  = true;

        return NSAPI_ERROR_OK;
    }

    return NSAPI_ERROR_NO_CONNECTION;
}

void SIMCom_SIM7020_CellularStack::urc_csonmi()
{
    const int sock_id = _at.read_int();
    tr_debug("urc_csonmi sock id: %d", static_cast<int>(sock_id));

    CellularSocket *sock;
    int i = 0;
    while (i < get_max_socket_count()) {
        sock = _socket[i];
        if (sock != NULL) {
            if (sock->id == sock_id) {
                tr_debug("sock->id: %d\n", static_cast<int>(sock->id));
                if (sock->_cb != NULL) {
                    const nsapi_size_t pending_bytes = _at.read_int();
                    MBED_ASSERT((pending_bytes / 2) <= sizeof(_rx_buffer));
                    const ssize_t read_bytes_err = _at.read_hex_string((char *)_rx_buffer,
                                                                       pending_bytes);
                    // Store rx context to socket to be accessed later in @ref socket_recvfrom_impl
                    sock->pending_bytes = (pending_bytes / 2);
                    MBED_ASSERT(sock->pending_bytes == static_cast<nsapi_size_t>(read_bytes_err));
                    tr_debug("urc_csonmi store pending bytes: %d\n", sock->pending_bytes);
                    sock->_cb(sock->_data);
                }

                break;
            }
        }
        ++i;
    }
}

void SIMCom_SIM7020_CellularStack::urc_socket_closed()
{
    const int sock_id = _at.read_int();
    tr_debug("urc_socket_closed sock id: %d", sock_id);
    const int err = _at.read_int();
    tr_debug("urc_socket_closed err: %d", err);

    switch (err) {
        CellularSocket *sock;
        case 4:
            sock = find_socket(sock_id);
            if (sock != NULL) {
                sock->closed = true;

                if (sock->_cb != NULL) {
                    sock->_cb(sock->_data);
                }
            }

            break;
        default:
#if 0
            /* @todo: Promote fast failure - add required implementation for product ready
             *        implementation. */
            MBED_ASSERT(false);
#endif
            break;
    }
}

int SIMCom_SIM7020_CellularStack::get_max_socket_count()
{
    return MAX_SOCKET;
}

bool SIMCom_SIM7020_CellularStack::is_protocol_supported(nsapi_protocol_t protocol)
{
    return (protocol == NSAPI_UDP || protocol == NSAPI_TCP);
}

nsapi_error_t SIMCom_SIM7020_CellularStack::socket_close_impl(int sock_id)
{
    CellularSocket *sock = find_socket(sock_id);
    MBED_ASSERT(sock != NULL);

    if (sock->closed) {
        return NSAPI_ERROR_OK;
    }

    _at.cmd_start("AT+CSOCL=");
    _at.write_int(sock_id);
    _at.cmd_stop_read_resp();

    return _at.get_last_error();
}

void SIMCom_SIM7020_CellularStack::handle_open_socket_response(int &modem_connect_id, int &err)
{
    MBED_ASSERT(false);
}

nsapi_error_t SIMCom_SIM7020_CellularStack::create_socket_impl(CellularSocket *socket)
{
    switch (socket->proto) {
        case NSAPI_UDP:
            _at.cmd_start("AT+CSOC=");
            _at.write_int(1);
            _at.write_int(2);
            _at.write_int(1);
            _at.write_int(_cid);
            _at.cmd_stop();

            break;
        case NSAPI_TCP:
            _at.cmd_start("AT+CSOC=");
            _at.write_int(1);
            _at.write_int(1);
            _at.write_int(1);
            _at.write_int(_cid);
            _at.cmd_stop();

            break;
        default:
            return NSAPI_ERROR_PARAMETER;
            break;
    }

    _at.resp_start("+CSOC:");
    socket->id = _at.read_int();
    _at.resp_stop();
#if 1
    const nsapi_error_t err = _at.get_last_error();
    MBED_ASSERT(err == NSAPI_ERROR_OK);
    MBED_ASSERT(socket->id >= 0);
#endif
#if 0
    const bool is_create_ok = ((_at.get_last_error() == NSAPI_ERROR_OK) &&  (socket->id >= 0));
    if (!is_create_ok) {
        tr_error("Socket create failed %d", socket->id);

        return NSAPI_ERROR_NO_SOCKET;
    }
#endif
    // Check for duplicate socket id delivered by modem
    CellularSocket *sock;
    for (unsigned int i = 0; (i < MAX_SOCKET); ++i) {
        sock = _socket[i];
        if (sock != NULL) {
            if (sock->created && (sock->id == socket->id)) {
                tr_error("Socket create failed: duplicate %d", socket->id);
MBED_ASSERT(false);
                return NSAPI_ERROR_NO_SOCKET;
            }
        }
    }

    tr_debug("Socket create id: %d", socket->id);
    socket->created = true;

    return NSAPI_ERROR_OK;
}

nsapi_size_or_error_t SIMCom_SIM7020_CellularStack::socket_sendto_impl(CellularSocket      *socket,
                                                                       const SocketAddress &address,
                                                                       const void          *data,
                                                                       nsapi_size_t         size)
{
    static char hexstr[MAX_SEND_SIZE * 2 + 1] = {0};
    int   hexlen;

    if (size > MAX_SEND_SIZE) {
        return NSAPI_ERROR_PARAMETER;
    }

    switch (socket->proto) {
        case NSAPI_UDP:
            if (socket->remoteAddress != address) {
                /* No existing connection endpoint setup in the modem for this remote peer, we need to create one here. */

                _address = address;
                _at.cmd_start("AT+CSOCON=");
                _at.write_int(socket->id);
                _at.write_int(address.get_port());
                _at.write_string(address.get_ip_address());
                _at.cmd_stop();

                _at.resp_start("+CSOCON:");
                _at.resp_stop();

                if (_at.get_last_error() != NSAPI_ERROR_OK)  {
                    return NSAPI_ERROR_DEVICE_ERROR;
                }

                socket->remoteAddress = address;
            }

            // Tx sequence.

//            hexstr         = new char[size * 2 + 1];
#if 0
            hexstr         = (char*)malloc(size * 2 + 1);
            MBED_ASSERT(hexstr != NULL);
#endif
            hexlen         = mbed_cellular_util::char_str_to_hex_str((const char *)data, size, hexstr);
            hexstr[hexlen] = 0;

            _at.cmd_start("AT+CSOSEND=");
            _at.write_int(socket->id);
            _at.write_int(hexlen);
            _at.write_string(hexstr, false);
            _at.cmd_stop_read_resp();

//            delete [] hexstr;
#if 0
            free(hexstr);
#endif

            if (_at.get_last_error() != NSAPI_ERROR_OK)  {
                return NSAPI_ERROR_DEVICE_ERROR;
            }

            return size;

            break;
        case NSAPI_TCP:
            hexlen         = mbed_cellular_util::char_str_to_hex_str((const char *)data, size, hexstr);
            hexstr[hexlen] = 0;

            _at.cmd_start("AT+CSOSEND=");
            _at.write_int(socket->id);
            _at.write_int(hexlen);
            _at.write_string(hexstr, false);
            _at.cmd_stop_read_resp();

            if (_at.get_last_error() != NSAPI_ERROR_OK)  {
                return NSAPI_ERROR_DEVICE_ERROR;
            }

            return size;
#if 0
            hexstr 		   = new char[size * 2 + 1];
            hexlen 		   = mbed_cellular_util::char_str_to_hex_str((const char *)data, size, hexstr);
            hexstr[hexlen] = 0;

            _at.cmd_start("AT+CSOSEND=");
            _at.write_int(socket->id);
            _at.write_int(hexlen);
            _at.write_string(hexstr, false);
            _at.cmd_stop_read_resp();

            delete [] hexstr;

            if (_at.get_last_error() != NSAPI_ERROR_OK)  {
                return NSAPI_ERROR_DEVICE_ERROR;
            }

            return size;
#endif
            break;
        default:
            return NSAPI_ERROR_PARAMETER;
            break;
    }
}

nsapi_size_or_error_t SIMCom_SIM7020_CellularStack::socket_recvfrom_impl(CellularSocket *socket,
                                                                         SocketAddress  *address,
                                                                         void           *buffer,
                                                                         nsapi_size_t    size)
{
    // Read all availabe rx data from the modem to the supplied buffer.
    MBED_ASSERT(size >= socket->pending_bytes);

#if 1
    tr_debug("RX input size: %d", static_cast<int>(size));
    tr_debug("RX socket id: %d\n", static_cast<int>(socket->id));
    tr_debug("RX socket->pending_bytes size: %d\n", static_cast<int>(socket->pending_bytes));
#endif
    const size_t rx_available = (socket->pending_bytes > size) ? size : socket->pending_bytes;

    if (rx_available == 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    tr_debug(">>>>>> L:RX copy size: %d", static_cast<int>(rx_available));

    memcpy(buffer, _rx_buffer, rx_available);
#if 0
    delete[] _rx_buffer;
#endif  // 0
#if 0
free(_rx_buffer);

	_rx_buffer            = NULL;
#endif
    socket->pending_bytes = 0;

    if (address != NULL) {
        address->set_ip_address(_address.get_ip_address());
        address->set_port(_address.get_port());
    }

    return rx_available;
}
