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
#include "SIMCom_SIM7020_CellularContext.h"
#include "SIMCom_SIM7020_CellularStack.h"
#include "CellularLog.h"

namespace mbed {

SIMCom_SIM7020_CellularContext::SIMCom_SIM7020_CellularContext(ATHandler      &at,
                                                               CellularDevice *device,
                                                               const char     *apn,
                                                               bool            cp_req,
                                                               bool            nonip_req) :
    AT_CellularContext(at, device, apn, cp_req, nonip_req)
{
#if 0
    if (_nonip_req) {
        _at.set_urc_handler("+QIND:", mbed::Callback<void()>(this, &QUECTEL_BG96_CellularContext::urc_nidd));
    }
#endif
}

SIMCom_SIM7020_CellularContext::~SIMCom_SIM7020_CellularContext()
{
}

bool SIMCom_SIM7020_CellularContext::stack_type_supported(nsapi_ip_stack_t stack_type)
{
    if (stack_type == IPV4_STACK) {
        return true;
    }
    return false;
}

#if !NSAPI_PPP_AVAILABLE
NetworkStack *SIMCom_SIM7020_CellularContext::get_stack()
{
    if (_pdp_type == NON_IP_PDP_TYPE || (_nonip_req && _pdp_type != DEFAULT_PDP_TYPE)) {
        tr_error("Requesting stack for NON-IP context! Should request control plane netif: get_cp_netif()");
        return NULL;
    }

    if (!_stack) {
        _stack = new SIMCom_SIM7020_CellularStack(_at, _cid, (nsapi_ip_stack_t)_pdp_type);
    }

    return _stack;
}
#endif // #if !NSAPI_PPP_AVAILABLE

#if 0
nsapi_error_t SIMCom_SIM7020_CellularContext::do_user_authentication()
{
    MBED_ASSERT(false);
#if 0
    if (_pwd && _uname) {
        _at.cmd_start("AT+QICSGP=");
        _at.write_int(_cid);
        _at.write_int(1); // IPv4
        _at.write_string(_apn);
        _at.write_string(_uname);
        _at.write_string(_pwd);
        _at.write_int(_authentication_type);
        _at.cmd_stop();
        _at.resp_start();
        _at.resp_stop();
        if (_at.get_last_error() != NSAPI_ERROR_OK) {
            return NSAPI_ERROR_AUTH_FAILURE;
        }
    }
#endif
    return NSAPI_ERROR_OK;
}
#endif
} /* namespace mbed */
