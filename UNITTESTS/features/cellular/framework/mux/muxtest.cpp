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
#include "gmock/gmock.h"
#include "mbed_mux.h"
#include "mbed_mux_base.h"
#include "FileHandle.h"
#include "EventQueue.h"
#include "Callback.h"
#include "equeue_stub.h"

using ::testing::Return;
using ::testing::_;
using ::testing::NotNull;
using ::testing::Invoke;
using ::testing::InSequence;

// AStyle ignored as the definition is not clear due to preprocessor usage
// *INDENT-OFF*
class TestMux : public testing::Test {
protected:

    void SetUp()
    {
    }

    void TearDown()
    {
    }
};
// *INDENT-ON*

#define FRAME_HEADER_READ_LEN        3u
#define FRAME_TRAILER_LEN            2u
#define FLAG_SEQUENCE_OCTET_LEN      1u                          /* Length of the flag sequence field in number of
                                                                    bytes. */
#define SABM_FRAME_LEN               6u                          /* Length of the SABM frame in number of bytes. */
#define DM_FRAME_LEN                 6u                          /* Length of the DM frame in number of bytes. */
#define UA_FRAME_LEN                 6u                          /* Length of the UA frame in number of bytes. */
#define UIH_FRAME_LEN                7u                          /* Length of the minium UIH frame in number of bytes.*/
#define WRITE_LEN                    1u                          /* Length of single write call in number of bytes. */
#define READ_LEN                     1u                          /* Length of single read call in number of bytes. */

#define FLAG_SEQUENCE_OCTET          0xF9u                       /* Flag field used in the basic option mode. */
#define ADDRESS_MUX_START_REQ_OCTET  0x03u                       /* Address field value of the start multiplexer
                                                                    request frame. */
#define ADDRESS_MUX_START_RESP_OCTET ADDRESS_MUX_START_REQ_OCTET /* Address field value of the start multiplexer
                                                                    response frame. */
#define LENGTH_INDICATOR_OCTET       1u                          /* Length indicator field value used in frame. */
#define T1_TIMER_VALUE               300u                        /* T1 timer value. */
#define T1_TIMER_EVENT_ID            1                           /* T1 timer event id. */
#define CRC_TABLE_LEN                256u                        /* CRC table length in number of bytes. */
#define RETRANSMIT_COUNT             3u                          /* Retransmission count for the tx frames requiring a
                                                                    response. */
#define PF_BIT                       (1u << 4)                   /* P/F bit position in the frame control field. */
#define CR_BIT                       (1u << 1)                   /* C/R bit position in the frame address field. */


#define FRAME_TYPE_SABM              0x2Fu                       /* SABM frame type coding in the frame control
                                                                    field. */
#define FRAME_TYPE_UA                0x63u                       /* UA frame type coding in the frame control field. */
#define FRAME_TYPE_DM                0x0Fu                       /* DM frame type coding in the frame control field. */
#define FRAME_TYPE_DISC              0x43u                       /* DISC frame type coding in the frame control
                                                                    field. */
#define FRAME_TYPE_UIH               0xEFu                       /* UIH frame type coding in the frame control field. */
#define FRAME_TYPE_UNSUPPORTED       0                           /* Unsupported frame type in the frame control field.
                                                                    Used for testing purpose. */

#define DLCI_ID_LOWER_BOUND          1u                          /* Lower bound DLCI id value. */
#define DLCI_ID_UPPER_BOUND          63u                         /* Upper bound DLCI id value. */
#define DLCI_INVALID_ID              0                           /* Invalid DLCI ID. Implementation uses to invalidate
                                                                    MuxDataService object. */

#define TX_BUFFER_SIZE               31u                         /* Size of the TX buffer in number of bytes. */
#define RX_BUFFER_SIZE               TX_BUFFER_SIZE              /* Size of the RX buffer in number of bytes. */

typedef enum
{
    READ_FLAG_SEQUENCE_OCTET = 0,
    SKIP_FLAG_SEQUENCE_OCTET
} FlagSequenceOctetReadType;


typedef enum
{
    STRIP_FLAG_FIELD_NO = 0,
    STRIP_FLAG_FIELD_YES
} StripFlagFieldType;

typedef enum
{
    ENQUEUE_DEFERRED_CALL_NO = 0,
    ENQUEUE_DEFERRED_CALL_YES
} EnqueueDeferredCallType;

static const uint8_t crctable[CRC_TABLE_LEN] = {
    0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75,  0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
    0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,  0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
    0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D,  0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
    0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51,  0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,

    0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,  0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
    0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19,  0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
    0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D,  0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
    0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,  0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,

    0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95,  0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
    0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89,  0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
    0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,  0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
    0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1,  0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,

    0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5,  0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
    0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,  0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
    0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD,  0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
    0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,  0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF
};

uint8_t fcs_calculate(const uint8_t *buffer,  uint8_t input_len)
{
    uint8_t fcs = 0xFFu;

    while (input_len-- != 0) {
        fcs = crctable[fcs^*buffer++];
    }

    /* Ones complement. */
    fcs = 0xFFu - fcs;

    return fcs;
}


class MockFileHandle : public mbed::FileHandle {

public:

    virtual ~MockFileHandle() {};

    MOCK_METHOD2(write, ssize_t(const void* buffer, size_t size));
    MOCK_METHOD2(read, ssize_t(void *buffer, size_t size));
    MOCK_METHOD1(set_blocking, int(bool blocking));
    MOCK_METHOD1(sigio, void(mbed::Callback<void()> func));

    virtual short poll(short events) const {return 0;}
    virtual off_t seek(off_t offset, int whence/* = SEEK_SET*/) {return 0;}
    virtual int close() {return 0;}
};


class MuxCallbackTest {

public:

    MuxCallbackTest() : _is_armed(false), _is_callback_set(false), _file_handle(NULL) {};

    virtual void channel_open_run(mbed::MuxBase::event_context_t &ev);
    bool is_callback_called();
    mbed::FileHandle *file_handle_get();
    void callback_arm();

protected:

    bool _is_armed;

private:

    bool              _is_callback_set;
    mbed::FileHandle *_file_handle;
};

void MuxCallbackTest::channel_open_run(mbed::MuxBase::event_context_t &ev)
{
    EXPECT_TRUE(_is_armed);
    EXPECT_EQ(mbed::MuxBase::EVENT_TYPE_OPEN, ev.event);

    _is_armed        = false;
    _is_callback_set = true;
    _file_handle     = ev.data.fh;
}


void MuxCallbackTest::callback_arm()
{
    EXPECT_FALSE(_is_armed);

    _is_armed = true;
}


bool MuxCallbackTest::is_callback_called()
{
    const bool ret   = _is_callback_set;
    _is_callback_set = false;

    return ret;
}


mbed::FileHandle *MuxCallbackTest::file_handle_get()
{
    mbed::FileHandle *fh = _file_handle;
    _file_handle         = NULL;

    return fh;
}


class FileWrite {

public:

    FileWrite() : _buffer(NULL), _size(0), _return(0) {};
    FileWrite(const void *buffer, size_t size, ssize_t return_value) : _buffer(buffer),
                                                                       _size(size),
                                                                       _return(return_value) {};

    void set(const void *buffer, size_t size, ssize_t return_value)
    {
        _buffer = buffer;
        _size   = size;
        _return = return_value;
    }

    ssize_t write(const void *buffer, size_t size)
    {
        EXPECT_EQ(_size, size);
        EXPECT_TRUE(memcmp(_buffer, buffer, _size) == 0);

        return _return;
    }

private:

    const void *_buffer;
    size_t      _size;
    ssize_t     _return;
};

class FileRead {

public:

    FileRead() : _buffer(NULL), _size(0), _return(0) {};
    FileRead(const void *buffer, size_t size, ssize_t return_value) : _buffer(buffer),
                                                                      _size(size),
                                                                      _return(return_value) {};

    void set(const void *buffer, size_t size, ssize_t return_value)
    {
        _buffer = buffer;
        _size   = size;
        _return = return_value;
    }

    ssize_t read(void *buffer, size_t size)
    {
        EXPECT_EQ(_size, size);
        memcpy(buffer, _buffer, _size);

        return _return;
    }

private:

    const void *_buffer;
    size_t      _size;
    ssize_t     _return;
};

class SigIo {

public:

    void sigio(mbed::Callback<void()> func)
    {
        _sigio_cb = func;
    }

    void dispatch()
    {
        _sigio_cb();
    }

private:

    mbed::Callback<void()> _sigio_cb;
};

/*
 * LOOP UNTIL COMPLETE REQUEST FRAME WRITE DONE
 * - trigger sigio callback from FileHandleMock
 * - enqueue deferred call to EventQueue
 * - CALL RETURN
 * - trigger deferred call from EventQueueMock
 * - call read
 * - call write
 * - call call_in in the last iteration for T1 timer
 * - CALL RETURN
 */
void self_iniated_request_tx(const uint8_t  *tx_buf,
                             uint8_t         tx_buf_len,
                             uint8_t         read_len,
                             MockFileHandle &fh,
                             SigIo          &sig_io)
{
    /* Write the complete request frame in the do...while. */

    uint8_t tx_count = 0;
    do {
        /* Enqueue deferred call to EventQueue.
         * Trigger sigio callback from the Filehandle used by the Mux3GPP (component under test). */
        mbed_equeue_stub::call_expect();
        sig_io.dispatch();

        /* Nothing to read. */
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();
        FileWrite write_1(&(tx_buf[tx_count]), (tx_buf_len - tx_count), 1);
        EXPECT_CALL(fh, write(NotNull(), (tx_buf_len - tx_count)))
                    .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();

        if (tx_count == tx_buf_len - 1) {
            /* Start frame write sequence gets completed, now start T1 timer. */
#if 0
            mock_t * mock_call_in = mock_free_get("call_in");
            CHECK(mock_call_in != NULL);
            mock_call_in->return_value = T1_TIMER_EVENT_ID;
            mock_call_in->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
            mock_call_in->input_param[0].param        = T1_TIMER_VALUE;
#endif
        } else {
            /* End the write cycle after successfull write made above in this loop. */
            FileWrite write_2(&(tx_buf[tx_count + 1u]), (tx_buf_len - (tx_count + 1u)), 0);
            EXPECT_CALL(fh, write(NotNull(), (tx_buf_len - (tx_count + 1u)))).WillOnce(Invoke(&write_2,
                        &FileWrite::write)).RetiresOnSaturation();
        }

        mbed_equeue_stub::deferred_dispatch();

        ++tx_count;
    } while (tx_count != tx_buf_len);
}


typedef enum
{
    CANCEL_TIMER_NO = 0,
    CANCEL_TIMER_YES
} CancelTimerType;

typedef enum
{
    START_TIMER_NO = 0,
    START_TIMER_YES
} StartTimerType;


/*
 * LOOP UNTIL COMPLETE REQUEST FRAME READ DONE
 * - trigger sigio callback from FileHandleMock
 * - enqueue deferred call to EventQueue
 * - CALL RETURN
 * - trigger deferred call from EventQueueMock
 * - call read
 * - complete response frame TX in the last iteration if parameter supplied
 * - CALL RETURN
 */
void peer_iniated_request_rx_full_frame_tx(FlagSequenceOctetReadType read_type,
                                           StripFlagFieldType        strip_flag_field_type,
                                           const uint8_t            *rx_buf,
                                           uint8_t                   rx_buf_len,
                                           const uint8_t            *write_byte,
                                           uint8_t                   tx_buf_len,
                                           CancelTimerType           cancel_timer,
                                           StartTimerType            start_timer,
                                           MockFileHandle           &fh,
                                           SigIo                    &sig_io)
{
    uint8_t rx_count = 0;

    /* Guard against internal logic error. */
    EXPECT_FALSE((read_type == READ_FLAG_SEQUENCE_OCTET) && (strip_flag_field_type == STRIP_FLAG_FIELD_YES));

    /* Enqueue deferred call to EventQueue.
     * Trigger sigio callback from the Filehandle used by the Mux3GPP (component under test). */
    mbed_equeue_stub::call_expect();
    sig_io.dispatch();

    if (read_type == READ_FLAG_SEQUENCE_OCTET) {
        /* Phase 1: read frame start flag. */
        FileRead read(&(rx_buf[rx_count]), FLAG_SEQUENCE_OCTET_LEN, 1);
        EXPECT_CALL(fh, read(NotNull(), FLAG_SEQUENCE_OCTET_LEN))
                    .WillOnce(Invoke(&read, &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
    }

    uint8_t read_len = FRAME_HEADER_READ_LEN;
    if (strip_flag_field_type == STRIP_FLAG_FIELD_YES) {
        /* Flag field present, which will be discarded by the implementation. */
ASSERT_TRUE(false); // @todo: implement me
#if 0
        mock_read = mock_free_get("read");
        CHECK(mock_read != NULL);
        mock_read->output_param[0].param       = &(rx_buf[rx_count]);
        mock_read->output_param[0].len         = sizeof(rx_buf[0]);
        mock_read->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_read->input_param[0].param        = read_len;
        mock_read->return_value                = 1;

        FileRead read(&(rx_buf[rx_count]), read_len, 1);
//        printf("TC this: 0x%08x\r\n", &read);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&read, &FileRead::read)).RetiresOnSaturation();
#endif
        ++rx_count;
    }

    /* Phase 2: read next 3 bytes 1-byte at a time. */
    FileRead *file_read_hdr = new FileRead[read_len];
    ASSERT_TRUE(file_read_hdr != NULL);
    do {
        /* Continue read cycle within current context. */
        file_read_hdr[read_len - 1].set(&(rx_buf[rx_count]), read_len, 1);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&(file_read_hdr[read_len - 1]),
                                                            &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
        --read_len;
    } while (read_len != 0);

    /* Phase 3: read trailing bytes after decoding length field 1-byte at a time. */
    read_len                    = FRAME_TRAILER_LEN;
    FileRead *file_read_trailer = new FileRead[read_len];
    ASSERT_TRUE(file_read_trailer != NULL);
    do {
        /* Continue read cycle within current context. */
        file_read_trailer[read_len - 1].set(&(rx_buf[rx_count]), read_len, 1);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&(file_read_trailer[read_len - 1]),
                                                                   &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
        --read_len;
    } while (read_len != 0);

    /* Cancel the T1 timer. */
    if (cancel_timer == CANCEL_TIMER_YES) {
#if 0
        mock_t * mock_cancel = mock_free_get("cancel");
        CHECK(mock_cancel != NULL);
        mock_cancel->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_cancel->input_param[0].param        = T1_TIMER_EVENT_ID;
#endif
    }

    /* Start the T1 timer for the new TX sequence. */
    if (start_timer == START_TIMER_YES) {
#if 0
        mock_t * mock_start = mock_free_get("call_in");
        CHECK(mock_start != NULL);
        mock_start->return_value                = T1_TIMER_EVENT_ID;
        mock_start->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_start->input_param[0].param        = T1_TIMER_VALUE;
#endif
    }

    /* RX frame completed, start the response frame TX sequence inside the current RX cycle. */
    uint8_t i             = 0;
    FileWrite *file_write = new FileWrite[tx_buf_len];
    ASSERT_TRUE(file_write != NULL);
    do {
        file_write[i].set(&(write_byte[i]), (tx_buf_len - i), 1);
        EXPECT_CALL(fh, write(NotNull(), (tx_buf_len - i))).WillOnce(Invoke(&(file_write[i]),
                                                                     &FileWrite::write)).RetiresOnSaturation();

        ++i;
    } while (i != tx_buf_len);

    /* Resume the Rx cycle and stop it. */
    EXPECT_CALL(fh, read(NotNull(), FRAME_HEADER_READ_LEN)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();

    mbed_equeue_stub::deferred_dispatch();

    /* Free all acquired dynamic resources within this function. */

    delete [] file_read_hdr;
    delete [] file_read_trailer;
    delete [] file_write;
}


/* Read complete response frame from the peer
 */
void self_iniated_response_rx(const uint8_t            *rx_buf,
                              const uint8_t            *resp_write_byte,
                              FlagSequenceOctetReadType read_type,
                              StripFlagFieldType        strip_flag_field_type,
                              EnqueueDeferredCallType   enqueue_deferred_call_type,
                              MockFileHandle           &fh,
                              SigIo                    &sig_io)
{
    /* Guard against internal logic error. */
    EXPECT_FALSE((read_type == READ_FLAG_SEQUENCE_OCTET) && (strip_flag_field_type == STRIP_FLAG_FIELD_YES));

    uint8_t rx_count = 0;
    if (enqueue_deferred_call_type == ENQUEUE_DEFERRED_CALL_YES) {
        /* Enqueue deferred call to EventQueue.
         * Trigger sigio callback from the Filehandle used by the Mux3GPP (component under test). */
        mbed_equeue_stub::call_expect();
        sig_io.dispatch();
    }

    if (read_type == READ_FLAG_SEQUENCE_OCTET) {
        /* Phase 1: read frame start flag. */
        FileRead read(&(rx_buf[rx_count]), FLAG_SEQUENCE_OCTET_LEN, 1);
        EXPECT_CALL(fh, read(NotNull(), FLAG_SEQUENCE_OCTET_LEN))
                    .WillOnce(Invoke(&read, &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
    }

    uint8_t read_len = FRAME_HEADER_READ_LEN;
    if (strip_flag_field_type == STRIP_FLAG_FIELD_YES) {
        /* Flag field present, which will be discarded by the implementation. */
        FileRead read(&(rx_buf[rx_count]), read_len, 1);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&read, &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
    }

    /* Phase 2: read next 3 bytes 1-byte at a time. */
    FileRead *file_read_hdr = new FileRead[read_len];
    ASSERT_TRUE(file_read_hdr != NULL);
    do {
        /* Continue read cycle within current context. */
        file_read_hdr[read_len - 1].set(&(rx_buf[rx_count]), read_len, 1);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&(file_read_hdr[read_len - 1]),
                                                            &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
        --read_len;
    } while (read_len != 0);

    /* Phase 3: read trailing bytes after decoding length field 1-byte at a time. */
    read_len                    = FRAME_TRAILER_LEN;
    FileRead *file_read_trailer = new FileRead[read_len];
    do {
        /* Continue read cycle within current context. */
        file_read_trailer[read_len - 1].set(&(rx_buf[rx_count]), read_len, 1);
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Invoke(&(file_read_trailer[read_len - 1]),
                                                            &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
        --read_len;
    } while (read_len != 0);

    /* Frame read sequence gets completed, now cancel T1 timer. */
#if 0
    // @todo: program "cancel"
    mock_t * mock_cancel = mock_free_get("cancel");
    CHECK(mock_cancel != NULL);
    mock_cancel->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
    mock_cancel->input_param[0].param        = T1_TIMER_EVENT_ID;
#endif
    if (resp_write_byte != NULL)  {
        /* RX frame completed, start the response frame TX sequence inside the current RX cycle. */
ASSERT_TRUE(false); //  @todo: implement this block
        const uint8_t length_of_frame = 4u + (resp_write_byte[3] & ~1) + 2u; // @todo: FIX ME: magic numbers.
#if 0
        mock_write = mock_free_get("write");
        CHECK(mock_write != NULL);
        mock_write->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->input_param[0].param        = (uint32_t)&(resp_write_byte[0]);
        mock_write->input_param[1].param        = length_of_frame;
        mock_write->input_param[1].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->return_value                = 1;

        /* End TX sequence: this call orginates from tx_internal_resp_entry_run(). */
        mock_write = mock_free_get("write");
        CHECK(mock_write != NULL);
        mock_write->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->input_param[0].param        = (uint32_t)&(resp_write_byte[1]);
        mock_write->input_param[1].param        = (length_of_frame - 1u);
        mock_write->input_param[1].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->return_value                = 0;

        /* End TX sequence: this call orginates from on_deferred_call(). */
        mock_write = mock_free_get("write");
        CHECK(mock_write != NULL);
        mock_write->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->input_param[0].param        = (uint32_t)&(resp_write_byte[1]);
        mock_write->input_param[1].param        = (length_of_frame - 1u);
        mock_write->input_param[1].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->return_value                = 0;
#endif
    }

    /* Resume the Rx cycle and stop it. */
    EXPECT_CALL(fh, read(NotNull(), FRAME_HEADER_READ_LEN)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();

    mbed_equeue_stub::deferred_dispatch();

    delete [] file_read_hdr;
    delete [] file_read_trailer;
}

/* Do successfull multiplexer self iniated open.*/
void mux_self_iniated_open(uint8_t                   tx_cycle_read_len,
                           FlagSequenceOctetReadType rx_cycle_read_type,
                           StripFlagFieldType        strip_flag_field_type,
                           MuxCallbackTest          &callback,
                           uint8_t                   frame_type,
                           mbed::Mux3GPP            &mux,
                           MockFileHandle           &fh,
                           SigIo                    &sig_io)
{
    const uint8_t write_byte[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    FileWrite write_1(&(write_byte[0]), sizeof(write_byte), 1);
    EXPECT_CALL(fh, write(NotNull(), SABM_FRAME_LEN))
                .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();
    FileWrite write_2(&(write_byte[1]), (sizeof(write_byte) - 1u), 0);
    EXPECT_CALL(fh, write(NotNull(), (SABM_FRAME_LEN - 1u)))
                .WillOnce(Invoke(&write_2, &FileWrite::write)).RetiresOnSaturation();

    /* Start test sequence. Test set mocks. */
    const nsapi_error channel_open_err = mux.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Finish the frame write sequence. */
    self_iniated_request_tx(&(write_byte[1]), (SABM_FRAME_LEN - 1u), tx_cycle_read_len, fh, sig_io);

    /* Read the mux open response frame. */
    const uint8_t read_byte[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_RESP_OCTET,
        (FRAME_TYPE_UA | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    /* Reception of the mux open response frame starts the channel creation procedure. */
    const uint32_t address                   = (3u) | (DLCI_ID_LOWER_BOUND << 2);
    const uint8_t write_byte_channel_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        address,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_channel_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_request_rx_full_frame_tx(rx_cycle_read_type, strip_flag_field_type,
                                          &(read_byte[0]), sizeof(read_byte),
                                          &(write_byte_channel_open[0]), sizeof(write_byte_channel_open),
                                          CANCEL_TIMER_YES, START_TIMER_YES,
                                          fh, sig_io);

    /* Read the channel open response frame. */
    const uint8_t read_byte_channel_open[5]  =
    {
        (3u | (1u << 2)),
        (frame_type | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte_channel_open[0], 3),
        FLAG_SEQUENCE_OCTET
    };
    callback.callback_arm();
    self_iniated_response_rx(&(read_byte_channel_open[0]), NULL, SKIP_FLAG_SEQUENCE_OCTET, STRIP_FLAG_FIELD_NO,
                             ENQUEUE_DEFERRED_CALL_YES,
                             fh, sig_io);
}


void mux_self_iniated_open(MuxCallbackTest &callback,
                           uint8_t          frame_type,
                           mbed::Mux3GPP   &mux,
                           MockFileHandle  &fh,
                           SigIo           &sig_io)
{
    mux_self_iniated_open(FLAG_SEQUENCE_OCTET_LEN,
                          READ_FLAG_SEQUENCE_OCTET,
                          STRIP_FLAG_FIELD_NO,
                          callback,
                          frame_type,
                          mux,
                          fh,
                          sig_io);
}


/*
 * TC - Ensure proper behaviour when channel is opened and multiplexer control channel is not open
 *
 * Test sequence:
 * - Send open multiplexer control channel request message
 * - Receive open multiplexer control channel response message
 * - Send open user channel request message
 * - Receive open user channel response message
 * - Generate channel open callbck with a  valid FileHandle
 *
 * Expected outcome:
 * - As specified above
 */
TEST_F(TestMux, channel_open_mux_not_open)
{
    InSequence dummy;

    mbed::Mux3GPP obj;

    events::EventQueue eq;
    obj.eventqueue_attach(&eq);

    MockFileHandle fh;
    SigIo          sig_io;
    EXPECT_CALL(fh, sigio(_)).Times(1).WillOnce(Invoke(&sig_io, &SigIo::sigio));
    EXPECT_CALL(fh, set_blocking(false)).WillOnce(Return(0));

    obj.serial_attach(&fh);

    MuxCallbackTest callback;
    obj.callback_attach(mbed::Callback<void(mbed::MuxBase::event_context_t &)>(&callback,
                        &MuxCallbackTest::channel_open_run), mbed::MuxBase::CHANNEL_TYPE_AT);

    mux_self_iniated_open(callback, FRAME_TYPE_UA, obj, fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);
}
