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
#include "TELIT_HE910_CellularContext.h"

namespace mbed {

TELIT_HE910_CellularContext::TELIT_HE910_CellularContext(ATHandler &at, CellularDevice *device, const char *apn, bool cp_req, bool nonip_req) :
        AT_CellularContext(at, device, apn, cp_req, nonip_req)
{
}

TELIT_HE910_CellularContext::~TELIT_HE910_CellularContext()
{
}

bool TELIT_HE910_CellularContext::pdp_type_supported(pdp_type_t pdp_type)
{
    return pdp_type == IPV4_PDP_TYPE ? true : false;
}

} /* namespace mbed */
