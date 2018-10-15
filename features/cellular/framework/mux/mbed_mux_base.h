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
#ifndef MUXBASE_H
#define MUXBASE_H

namespace mbed {

class FileHandle;
class MuxBase {
public:

    /* Definition for channel type. */
    typedef enum {
        CHANNEL_TYPE_AT = 0,
        CHANNEL_TYPE_NVM,
        CHANNEL_TYPE_BIP,
        CHANNEL_TYPE_MAX
    } ChannelType;

    /* Definition for event type. */
    typedef enum {
        EVENT_TYPE_OPEN = 0,
        EVENT_TYPE_CLOSE,
        EVENT_TYPE_MAX
    } EventType;

    /* Definition for event data. */
    typedef struct {
        FileHandle *fh; /* Filehandle object identifier. */
    } event_data_t;

    /* Definition for event context. */
    typedef struct {
        EventType    event; /* Event type. */
        event_data_t data;  /* Event data. */
    } event_context_t;

};

} // namespace mbed

#endif
