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
#include "gtest/gtest.h"
#include <string.h>
#include "AT_ControlPlane_netif.h"
#include "EventQueue.h"
#include "ATHandler.h"
#include "FileHandle_stub.h"
#include "ATHandler_stub.h"

#include "AT_CellularBase_stub.h"

using namespace mbed;
using namespace events;

// AStyle ignored as the definition is not clear due to preprocessor usage
// *INDENT-OFF*
class TestAT_ControlPlane_netif : public testing::Test {
protected:

    void SetUp()
    {
    }

    void TearDown()
    {
    }
};

TEST_F(TestAT_ControlPlane_netif, Create)
{
    EventQueue eq;
    FileHandle_stub fh;
    ATHandler ah(&fh, eq, 0, ",");
    AT_ControlPlane_netif *unit = new AT_ControlPlane_netif(ah, 0);
    EXPECT_TRUE(unit != NULL);
    delete unit;
}

TEST_F(TestAT_ControlPlane_netif, send)
{
}

TEST_F(TestAT_ControlPlane_netif, recv)
{
}
