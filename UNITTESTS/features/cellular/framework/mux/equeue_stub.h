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
#ifndef __EQUEUE_STUB_H__
#define __EQUEUE_STUB_H__

typedef void (*mbed_equeue_stub_cb_func_t)(void*);

namespace mbed_equeue_stub {
extern int is_call_in_ms;
extern bool is_call_armed;
extern bool is_call_in_armed;
extern bool is_delay_called;
extern mbed_equeue_stub_cb_func_t timer_cb;
extern mbed_equeue_stub_cb_func_t deferred_cb;
extern void *timer_cb_cntx;
extern void *deferred_cb_cntx;

void deferred_dispatch();
void timer_dispatch();
void call_expect();
void call_in_expect(int ms);
};

#endif
