/*
 * Copyright (c) 2018, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "TCPSocket.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest.h"
#include "tcp_tests.h"

using namespace utest::v1;

namespace {
static const int SIGNAL_SIGIO = 0x1;
static const int SIGIO_TIMEOUT = 20000; //[ms]

static const int BUFF_SIZE = 1200;
static const int PKTS = 22;
static const int pkt_sizes[PKTS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
                                    100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, \
                                    1100, 1200
                                   };

/*static const int pkt_sizes[PKTS] = {1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, \
                                    1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, \
                                    1021, 1022, 1023, 1014, 1025, 1026, 1027, 1028, 1029, 1030, \
                                    1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, \
                                    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, \
                                    1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, \
                                    1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, \
                                    1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, \
                                    1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, \
                                    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, \
                                    1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, \
                                    1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, \
                                    1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, \
                                    1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, \
                                    1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, \
                                    1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, \
                                    1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, \
                                    1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, \
                                    1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, \
                                    1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, \
                                    1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, \
                                    1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220,
                                    //1000, 1000
                                   };*/
TCPSocket sock;
Semaphore tx_sem(0, 1);
events::EventQueue *event_queue;
int bytes2recv;
int bytes2recv_total;

Timer tc_exec_time;
int time_allotted;
bool receive_error;
}

void tcpsocket_echotest_nonblock_receive();

static void _sigio_handler(osThreadId id)
{
    osSignalSet(id, SIGNAL_SIGIO);
    if (event_queue != NULL) {
        event_queue->call(tcpsocket_echotest_nonblock_receive);
    } else {
        TEST_FAIL_MESSAGE("_sigio_handler running when event_queue is NULL");
    }
}

void TCPSOCKET_ECHOTEST()
{
    SKIP_IF_TCP_UNSUPPORTED();
    if (tcpsocket_connect_to_echo_srv(sock) != NSAPI_ERROR_OK) {
        TEST_FAIL();
        return;
    }

    int recvd;
    int sent;
    for (int s_idx = 0; s_idx < sizeof(pkt_sizes) / sizeof(*pkt_sizes); s_idx++) {
        int pkt_s = pkt_sizes[s_idx];
        fill_tx_buffer_ascii(tcp_global::tx_buffer, BUFF_SIZE);
        sent = sock.send(tcp_global::tx_buffer, pkt_s);
        if (sent < 0) {
            printf("[Round#%02d] network error %d\n", s_idx, sent);
            TEST_FAIL();
            break;
        } else if (sent != pkt_s) {
            printf("[%02d] sock.send return size %d does not match the expectation %d\n", s_idx, sent, pkt_s);
            TEST_FAIL();
            break;
        }

        int bytes2recv = sent;
        while (bytes2recv) {
            recvd = sock.recv(&(tcp_global::rx_buffer[sent - bytes2recv]), bytes2recv);
            if (recvd < 0) {
                printf("[Round#%02d] network error %d\n", s_idx, recvd);
                TEST_FAIL();
                TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock.close());
                return;
            } else if (recvd > bytes2recv) {
                TEST_FAIL_MESSAGE("sock.recv returned more bytes than requested");
            }
            bytes2recv -= recvd;
        }
        TEST_ASSERT_EQUAL(0, memcmp(tcp_global::tx_buffer, tcp_global::rx_buffer, sent));
    }
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock.close());
}

void tcpsocket_echotest_nonblock_receive()
{
    while (bytes2recv > 0) {
        int recvd = sock.recv(&(tcp_global::rx_buffer[bytes2recv_total - bytes2recv]), bytes2recv);
        if (recvd == NSAPI_ERROR_WOULD_BLOCK) {
            if (tc_exec_time.read() >= time_allotted) {
                TEST_FAIL_MESSAGE("time_allotted exceeded");
                receive_error = true;
            }
            return;
        } else if (recvd < 0) {
            printf("sock.recv returned an error %d", recvd);
            TEST_FAIL();
            receive_error = true;
        } else {
            bytes2recv -= recvd;
        }

        if (bytes2recv == 0) {
            TEST_ASSERT_EQUAL(0, memcmp(tcp_global::tx_buffer, tcp_global::rx_buffer, bytes2recv_total));
            tx_sem.release();
        } else if (receive_error || bytes2recv < 0) {
            TEST_FAIL();
            tx_sem.release();
        }
        // else - no error, not all bytes were received yet.
    }
}

void TCPSOCKET_ECHOTEST_NONBLOCK()
{
    SKIP_IF_TCP_UNSUPPORTED();
    tc_exec_time.start();
    time_allotted = split2half_rmng_tcp_test_time(); // [s]

    EventQueue queue(2 * EVENTS_EVENT_SIZE);
    event_queue = &queue;

    tcpsocket_connect_to_echo_srv(sock);
    sock.set_blocking(false);
    sock.sigio(callback(_sigio_handler, ThisThread::get_id()));

    int bytes2send;
    int sent;
    receive_error = false;
    unsigned char *stack_mem = (unsigned char *)malloc(tcp_global::TCP_OS_STACK_SIZE);
    TEST_ASSERT_NOT_NULL(stack_mem);
    Thread *receiver_thread = new Thread(osPriorityNormal,
                                         tcp_global::TCP_OS_STACK_SIZE,
                                         stack_mem,
                                         "receiver");

    TEST_ASSERT_EQUAL(osOK, receiver_thread->start(callback(&queue, &EventQueue::dispatch_forever)));

    for (int s_idx = 0; s_idx < sizeof(pkt_sizes) / sizeof(*pkt_sizes); ++s_idx) {
        int pkt_s = pkt_sizes[s_idx];
        bytes2recv = pkt_s;
        bytes2recv_total = pkt_s;

        fill_tx_buffer_ascii(tcp_global::tx_buffer, pkt_s);

        bytes2send = pkt_s;
        while (bytes2send > 0) {
            sent = sock.send(&(tcp_global::tx_buffer[pkt_s - bytes2send]), bytes2send);
            if (sent == NSAPI_ERROR_WOULD_BLOCK) {
                if (tc_exec_time.read() >= time_allotted ||
                        osSignalWait(SIGNAL_SIGIO, SIGIO_TIMEOUT).status == osEventTimeout) {
                    TEST_FAIL();
                    goto END;
                }
                continue;
            } else if (sent <= 0) {
                printf("[Sender#%02d] network error %d\n", s_idx, sent);
                TEST_FAIL();
                goto END;
            }
            bytes2send -= sent;
        }
#if MBED_CONF_NSAPI_SOCKET_STATS_ENABLED
        int count = fetch_stats();
        int j;
        for (j = 0; j < count; j++) {
            if ((tcp_stats[j].state == SOCK_OPEN) && (tcp_stats[j].proto == NSAPI_TCP)) {
                break;
            }
        }
        TEST_ASSERT_EQUAL(bytes2send, tcp_stats[j].sent_bytes);
#endif
        tx_sem.try_acquire_for(split2half_rmng_tcp_test_time() * 1000); // *1000 to convert s->ms
        if (receive_error) {
            break;
        }
    }
END:
    sock.sigio(NULL);
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock.close());
    receiver_thread->terminate();
    delete receiver_thread;
    receiver_thread = NULL;
    tc_exec_time.stop();
    free(stack_mem);
}
