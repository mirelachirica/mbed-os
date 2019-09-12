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
#include "UDPSocket.h"
#include "EventFlags.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest.h"
#include "udp_tests.h"

using namespace utest::v1;

namespace {
static const int SIGNAL_SIGIO_RX = 0x1;
static const int SIGNAL_SIGIO_TX = 0x2;
static const int SIGIO_TIMEOUT = 5000; //[ms]
static const int RETRIES = 2;

static const double EXPECTED_LOSS_RATIO = 0.0;
static const double TOLERATED_LOSS_RATIO = 0.3;

UDPSocket *sock;
EventFlags signals;

static const int BUFF_SIZE = 1200;
char rx_buffer[BUFF_SIZE] = {0};
char tx_buffer[BUFF_SIZE] = {0};

static const int PKTS = 22;
static const int pkt_sizes[PKTS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
                                    100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, \
                                    1100, 1200
                                   };

//static const int pkt_sizes[PKTS] = {1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, \
//                                    1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, \
//                                    1021, 1022, 1023, 1014, 1025, 1026, 1027, 1028, 1029, 1030, \
//                                    1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, \
//                                    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, \
//                                    1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, \
//                                    1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, \
//                                    1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, \
//                                    1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, \
//                                    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, \
//                                    1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, \
//                                    1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, \
//                                    1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, \
//                                    1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, \
//                                    1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, \
//                                    1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, \
//                                    1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, \
//                                    1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, \
//                                    1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, \
//                                    1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, \
//                                    1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, \
//                                    1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220,
//                                    //1000, 1000
//                                   };
Timer tc_exec_time;
int time_allotted;
}

static void _sigio_handler()
{
    signals.set(SIGNAL_SIGIO_RX | SIGNAL_SIGIO_TX);
}

void UDPSOCKET_ECHOTEST()
{
    SocketAddress udp_addr;
    NetworkInterface::get_default_instance()->gethostbyname(ECHO_SERVER_ADDR, &udp_addr);
    udp_addr.set_port(ECHO_SERVER_PORT);

    UDPSocket sock;
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock.open(NetworkInterface::get_default_instance()));

    int recvd;
    int sent;
    int packets_sent = 0;
    int packets_recv = 0;
    for (unsigned int s_idx = 0; s_idx < sizeof(pkt_sizes) / sizeof(*pkt_sizes); ++s_idx) {
        int pkt_s = pkt_sizes[s_idx];

        fill_tx_buffer_ascii(tx_buffer, BUFF_SIZE);
        int packets_sent_prev = packets_sent;

        for (int retry_cnt = 0; retry_cnt <= 2; retry_cnt++) {
            memset(rx_buffer, 0, BUFF_SIZE);
            sent = sock.sendto(udp_addr, tx_buffer, pkt_s);
            if (check_oversized_packets(sent, pkt_s)) {
                TEST_IGNORE_MESSAGE("This device does not handle oversized packets");
            } else if (sent == pkt_s) {
                packets_sent++;
            } else {
                printf("[Round#%02d - Sender] error, returned %d\n", s_idx, sent);
                continue;
            }
            recvd = sock.recvfrom(NULL, rx_buffer, pkt_s);
            if (recvd == pkt_s) {
                break;
            } else {
                printf("[Round#%02d - Receiver] error, returned %d\n", s_idx, recvd);
            }
        }
        if (memcmp(tx_buffer, rx_buffer, pkt_s) == 0) {
            packets_recv++;
        }
        // Make sure that at least one packet of every size was sent.
        TEST_ASSERT_TRUE(packets_sent > packets_sent_prev);
    }

    // Packet loss up to 30% tolerated
    if (packets_sent > 0) {
        double loss_ratio = 1 - ((double)packets_recv / (double)packets_sent);
        printf("Packets sent: %d, packets received %d, loss ratio %.2lf\r\n", packets_sent, packets_recv, loss_ratio);
        TEST_ASSERT_DOUBLE_WITHIN(TOLERATED_LOSS_RATIO, EXPECTED_LOSS_RATIO, loss_ratio);
    }
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock.close());
}

void UDPSOCKET_ECHOTEST_NONBLOCK()
{
    tc_exec_time.start();
    time_allotted = split2half_rmng_udp_test_time(); // [s]

    SocketAddress udp_addr;
    NetworkInterface::get_default_instance()->gethostbyname(ECHO_SERVER_ADDR, &udp_addr);
    udp_addr.set_port(ECHO_SERVER_PORT);
    sock = new UDPSocket();
    if (sock == NULL) {
        TEST_FAIL_MESSAGE("UDPSocket not created");
        return;
    }
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock->open(NetworkInterface::get_default_instance()));
    sock->set_blocking(false);
    sock->sigio(callback(_sigio_handler));
    int sent;
    int packets_sent = 0;
    int packets_recv = 0;
    for (unsigned int s_idx = 0; s_idx < sizeof(pkt_sizes) / sizeof(*pkt_sizes); ++s_idx) {
        int pkt_s = pkt_sizes[s_idx];
        int packets_sent_prev = packets_sent;
        for (int retry_cnt = 0; retry_cnt <= RETRIES; retry_cnt++) {
            fill_tx_buffer_ascii(tx_buffer, pkt_s);

            sent = sock->sendto(udp_addr, tx_buffer, pkt_s);
            if (sent == pkt_s) {
                packets_sent++;
            } else if (sent == NSAPI_ERROR_WOULD_BLOCK) {
                if (tc_exec_time.read() >= time_allotted ||
                        signals.wait_all(SIGNAL_SIGIO_TX, SIGIO_TIMEOUT) == osFlagsErrorTimeout) {
                    continue;
                }
                --retry_cnt;
            } else {
                printf("[Round#%02d - Sender] error, returned %d\n", s_idx, sent);
                continue;
            }

            int recvd;
            for (int retry_recv = 0; retry_recv <= RETRIES; retry_recv++) {
                recvd = sock->recvfrom(NULL, rx_buffer, pkt_s);
                if (recvd == NSAPI_ERROR_WOULD_BLOCK) {
                    if (tc_exec_time.read() >= time_allotted) {
                        break;
                    }
                    signals.wait_all(SIGNAL_SIGIO_RX, SIGIO_TIMEOUT);
                    --retry_recv;
                    continue;
                } else if (recvd < 0) {
                    printf("sock.recvfrom returned %d\n", recvd);
                    TEST_FAIL();
                    break;
                } else if (recvd == pkt_s) {
                    break;
                }
            }

            if (recvd == pkt_s) {
                break;
            }
        }
        // Make sure that at least one packet of every size was sent.
        TEST_ASSERT_TRUE(packets_sent > packets_sent_prev);
        if (memcmp(tx_buffer, rx_buffer, pkt_s) == 0) {
            packets_recv++;
        }
    }

    // Packet loss up to 30% tolerated
    if (packets_sent > 0) {
        double loss_ratio = 1 - ((double)packets_recv / (double)packets_sent);
        printf("Packets sent: %d, packets received %d, loss ratio %.2lf\r\n", packets_sent, packets_recv, loss_ratio);
        TEST_ASSERT_DOUBLE_WITHIN(TOLERATED_LOSS_RATIO, EXPECTED_LOSS_RATIO, loss_ratio);

#if MBED_CONF_NSAPI_SOCKET_STATS_ENABLED
        int count = fetch_stats();
        int j = 0;
        for (; j < count; j++) {
            if ((NSAPI_UDP == udp_stats[j].proto) && (SOCK_OPEN == udp_stats[j].state)) {
                TEST_ASSERT(udp_stats[j].sent_bytes != 0);
                TEST_ASSERT(udp_stats[j].recv_bytes != 0);
                break;
            }
        }
        loss_ratio = 1 - ((double)udp_stats[j].recv_bytes / (double)udp_stats[j].sent_bytes);
        printf("Bytes sent: %d, bytes received %d, loss ratio %.2lf\r\n", udp_stats[j].sent_bytes, udp_stats[j].recv_bytes, loss_ratio);
        TEST_ASSERT_DOUBLE_WITHIN(TOLERATED_LOSS_RATIO, EXPECTED_LOSS_RATIO, loss_ratio);

#endif
    }
    TEST_ASSERT_EQUAL(NSAPI_ERROR_OK, sock->close());
    delete sock;
    tc_exec_time.stop();
}
