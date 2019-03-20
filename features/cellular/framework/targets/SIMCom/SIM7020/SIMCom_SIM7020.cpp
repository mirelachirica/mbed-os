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

#include "SIMCom_SIM7020.h"
#include "SIMCom_SIM7020_CellularNetwork.h"
#include "SIMCom_SIM7020_CellularContext.h"
#include "SIMCom_SIM7020_CellularInformation.h"

using namespace mbed;

#define DEVICE_READY_URC "CPIN:"

static const intptr_t cellular_properties[AT_CellularBase::PROPERTY_MAX] = {
    0,    // C_EREG
    AT_CellularNetwork::RegistrationModeLAC,    // C_GREG
    0,    // C_REG
    0,  // AT_CGSN_WITH_TYPE
    0,  // AT_CGDATA
    1,  // AT_CGAUTH
    1,  // PROPERTY_IPV4_STACK
    0,  // PROPERTY_IPV6_STACK
    0,  // PROPERTY_IPV4V6_STACK
    0,  // PROPERTY_NON_IP_PDP_TYPE
};

SIMCom_SIM7020::SIMCom_SIM7020(FileHandle *fh) : AT_CellularDevice(fh)
{
    AT_CellularBase::set_cellular_properties(cellular_properties);
}

SIMCom_SIM7020::~SIMCom_SIM7020()
{
}

AT_CellularNetwork *SIMCom_SIM7020::open_network_impl(ATHandler &at)
{
    return new SIMCom_SIM7020_CellularNetwork(at);
}

AT_CellularContext *SIMCom_SIM7020::create_context_impl(ATHandler &at, const char *apn, bool cp_req, bool nonip_req)
{
    return new SIMCom_SIM7020_CellularContext(at, this, apn, cp_req, nonip_req);
}

AT_CellularInformation *SIMCom_SIM7020::open_information_impl(ATHandler &at)
{
    return new SIMCom_SIM7020_CellularInformation(at);
}

void SIMCom_SIM7020::set_ready_cb(Callback<void()> callback)
{
    _at->set_urc_handler(DEVICE_READY_URC, callback);
}

#include "mbed.h"
nsapi_error_t SIMCom_SIM7020::hard_power_on()
{
    DigitalOut modem_power_on(PE_15);
    modem_power_on = 1;
    Thread::wait(10000);
}


#if MBED_CONF_SIMCOM_SIM7020_PROVIDE_DEFAULT
#include "UARTSerial.h"
CellularDevice *CellularDevice::get_default_instance()
{
    static UARTSerial serial(MBED_CONF_SIMCOM_SIM7020_TX/*SERIAL_TX1*/,
                             MBED_CONF_SIMCOM_SIM7020_RX/*SERIAL_RX1*/,
                             MBED_CONF_SIMCOM_SIM7020_BAUDRATE);
#if defined (MBED_CONF_UBLOX_AT_RTS) && defined(MBED_CONF_UBLOX_AT_CTS)
#if 0
    tr_debug("SIMCOM_SIM7020 flow control: RTS %d CTS %d", MBED_CONF_SIMCOM_SIM7020_RTS, MBED_CONF_SIMCOM_SIM7020_CTS);
    serial.set_flow_control(SerialBase::RTSCTS, MBED_CONF_SIMCOM_SIM7020_RTS, MBED_CONF_SIMCOM_SIM7020_CTS);
#endif
#endif
    static SIMCom_SIM7020 device(&serial);
    return &device;
}
#endif
