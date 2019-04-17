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

#include "SIMCom_SIM7020_CellularNetwork.h"

using namespace mbed;

SIMCom_SIM7020_CellularNetwork::SIMCom_SIM7020_CellularNetwork(ATHandler &atHandler) : AT_CellularNetwork(atHandler)
{
}

SIMCom_SIM7020_CellularNetwork::~SIMCom_SIM7020_CellularNetwork()
{
}

nsapi_error_t SIMCom_SIM7020_CellularNetwork::set_access_technology_impl(RadioAccessTechnology opsAct)
{
    MBED_ASSERT(false);
#if 0
    _at.lock();

    switch (opsAct) {
        case RAT_CATM1:
            _at.cmd_start("AT+QCFG=\"nwscanseq\",020301");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"nwscanmode\",3,1");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"iotopmode\",0,1");
            _at.cmd_stop_read_resp();
            break;
        case RAT_NB1:
            _at.cmd_start("AT+QCFG=\"nwscanseq\",030201");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"nwscanmode\",3,1");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"iotopmode\",1,1");
            _at.cmd_stop_read_resp();
            break;
        case RAT_GSM:
        case RAT_GSM_COMPACT:
        case RAT_UTRAN:
        case RAT_EGPRS:
            _at.cmd_start("AT+QCFG=\"nwscanseq\",010203");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"nwscanmode\",1,1");
            _at.cmd_stop_read_resp();
            break;
        default:
            _at.cmd_start("AT+QCFG=\"nwscanseq\",020301");
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"nwscanmode\",0,1"); //auto mode
            _at.cmd_stop_read_resp();
            _at.cmd_start("AT+QCFG=\"iotopmode\",2,1"); //auto mode
            _at.cmd_stop_read_resp();
            _at.unlock();
            _op_act = RAT_UNKNOWN;
            return NSAPI_ERROR_UNSUPPORTED;
    }

    return _at.unlock_return_error();
#endif
}
