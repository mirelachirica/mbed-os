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

} /* namespace mbed */
