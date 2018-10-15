/*
 * Copyright (c) , Arm Limited and affiliates.
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

#include "equeue.h"
#include "equeue_stub.h"
#include <stdlib.h>
#include <stdio.h>

bool mbed_equeue_stub::call_in_within_call_context       = true;
bool mbed_equeue_stub::is_delay_called                   = false;
mbed_equeue_stub_cb_func_t mbed_equeue_stub::timer_cb    = NULL;
mbed_equeue_stub_cb_func_t mbed_equeue_stub::deferred_cb = NULL;
void *mbed_equeue_stub::timer_cb_cntx                    = NULL;
void *mbed_equeue_stub::deferred_cb_cntx                 = NULL;

namespace mbed_equeue_stub {

void deferred_dispatch()
{
printf("deferred_dispatch\r\n");
    deferred_cb(deferred_cb_cntx);
}

void timer_dispatch()
{
//printf("timer_dispatch\r\n");
    timer_cb(timer_cb_cntx);
}

}

int equeue_create(equeue_t *queue, size_t size)
{
    return 0;
}

int equeue_create_inplace(equeue_t *queue, size_t size, void *buffer)
{
    return 0;
}

void equeue_destroy(equeue_t *queue)
{

}

void equeue_dispatch(equeue_t *queue, int ms)
{

}

void equeue_break(equeue_t *queue)
{

}

int equeue_call(equeue_t *queue, void (*cb)(void *), void *data)
{
//printf("!!equeue_call\r\n");
    return 0;
}

int equeue_call_every(equeue_t *queue, int ms, void (*cb)(void *), void *data)
{
    return 0;
}

void *equeue_alloc(equeue_t *queue, size_t size)
{
    return malloc(size);
}

void equeue_dealloc(equeue_t *queue, void *event)
{

}

void equeue_event_delay(void *event, int ms)
{
    mbed_equeue_stub::is_delay_called = true;
}

void equeue_event_period(void *event, int ms)
{

}

void equeue_event_dtor(void *event, void (*dtor)(void *))
{

}

int equeue_post(equeue_t *queue, void (*cb)(void *), void *event)
{
//printf("equeue_post\r\n");
    if (cb)
    {
        if (mbed_equeue_stub::is_delay_called) {
            mbed_equeue_stub::is_delay_called = false;
//printf("store timer\r\n");
            mbed_equeue_stub::timer_cb        = cb;
            mbed_equeue_stub::timer_cb_cntx   = event;
        } else {
//printf("store deferred\r\n");
            mbed_equeue_stub::deferred_cb      = cb;
            mbed_equeue_stub::deferred_cb_cntx = event;
        }

        if (mbed_equeue_stub::call_in_within_call_context) {
            cb(event);
        }
#if 0
        free(event);
#endif
        return 1; //Fake ID for calling cancel

    }
    return 0;
}

void equeue_cancel(equeue_t *queue, int id)
{

}

void equeue_background(equeue_t *queue,
                       void (*update)(void *timer, int ms), void *timer)
{

}

void equeue_chain(equeue_t *queue, equeue_t *target)
{

}

int equeue_call_in(equeue_t *q, int ms, void (*cb)(void*), void *data) {
//printf("equeue_call_in\r\n");
    // The stub does not implement the delay mechanism.
    return equeue_post(q, cb, data);
}
