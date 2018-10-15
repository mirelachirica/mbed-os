/* mbed Microcontroller Library
 * Copyright (c) 2018 ARM Limited
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
#ifndef MUXDATASERVICEBASE_H
#define MUXDATASERVICEBASE_H

#include <stdint.h>
#include "FileHandle.h"

namespace mbed {

class MuxDataServiceBase : public FileHandle {

protected:

    virtual ~MuxDataServiceBase() {};

    MuxDataServiceBase() {};

    Callback<void()> _sigio_cb; /* Registered signal callback. */

private:

    /* Deny copy constructor. */
    MuxDataServiceBase(const MuxDataServiceBase &obj);

    /* Deny assignment operator. */
    MuxDataServiceBase &operator=(const MuxDataServiceBase &obj);
};

} // namespace mbed

#endif
