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
        mbed_equeue_stub::call_expect(1);
        sig_io.dispatch();

        /* Nothing to read. */
        EXPECT_CALL(fh, read(NotNull(), read_len)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();
        FileWrite write_1(&(tx_buf[tx_count]), (tx_buf_len - tx_count), 1);
        EXPECT_CALL(fh, write(NotNull(), (tx_buf_len - tx_count)))
                    .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();

        if (tx_count == tx_buf_len - 1) {
            /* Start frame write sequence gets completed, now start T1 timer. */
            mbed_equeue_stub::call_in_expect(T1_TIMER_VALUE, 1);
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
    mbed_equeue_stub::call_expect(1);
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
        mbed_equeue_stub::cancel_expect(1);
    }

    /* Start the T1 timer for the new TX sequence. */
    if (start_timer == START_TIMER_YES) {
        mbed_equeue_stub::call_in_expect(T1_TIMER_VALUE, 1);
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
        mbed_equeue_stub::call_expect(1);
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
    mbed_equeue_stub::cancel_expect(1);

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
 * LOOP UNTIL COMPLETE REQUEST FRAME READ DONE
 * - trigger sigio callback from FileHandleMock
 * - enqueue deferred call to EventQueue
 * - CALL RETURN
 * - trigger deferred call from EventQueueMock
 * - call read
 * - begin response frame TX sequence in the last iteration if parameter supplied
 * - call read
 * - CALL RETURN
 */
void peer_iniated_request_rx(const uint8_t            *rx_buf,
                             FlagSequenceOctetReadType read_type,
                             const uint8_t            *resp_write_byte,
                             const uint8_t            *current_tx_write_byte,
                             uint8_t                   current_tx_write_byte_len,
                             MockFileHandle           &fh,
                             SigIo                    &sig_io)
{
    /* Internal logic error if both supplied params are != NULL. */
    EXPECT_FALSE((resp_write_byte != NULL) && (current_tx_write_byte != NULL));

    /* Phase 1: read frame start flag. */

    uint8_t rx_count = 0;

    /* Enqueue deferred call to EventQueue.
     * Trigger sigio callback from the Filehandle used by the Mux3GPP (component under test). */
    mbed_equeue_stub::call_expect(1);
    sig_io.dispatch();

    if (read_type == READ_FLAG_SEQUENCE_OCTET) {
        /* Phase 1: read frame start flag. */
        FileRead read(&(rx_buf[rx_count]), FLAG_SEQUENCE_OCTET_LEN, 1);
        EXPECT_CALL(fh, read(NotNull(), FLAG_SEQUENCE_OCTET_LEN))
                    .WillOnce(Invoke(&read, &FileRead::read)).RetiresOnSaturation();

        ++rx_count;
    }

    /* Phase 2: read next 3 bytes 1-byte at a time. */
    uint8_t read_len        = FRAME_HEADER_READ_LEN;
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

    /* Resume the Rx cycle and stop it. */

    if (resp_write_byte != NULL)  {
        /* RX frame completed, start the response frame TX sequence inside the current RX cycle. */

        const uint8_t length_of_frame = 4u + (resp_write_byte[3] & ~1) + 2u; // @todo: FIX ME: magic numbers.

        FileWrite write_1(&(resp_write_byte[0]), length_of_frame, 1);
        EXPECT_CALL(fh, write(NotNull(), length_of_frame))
                    .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();

        /* End TX sequence: this call orginates from tx_internal_resp_entry_run(). */
        FileWrite write_2(&(resp_write_byte[1]), (length_of_frame - 1u), 0);
        EXPECT_CALL(fh, write(NotNull(), (length_of_frame - 1u)))
                    .WillOnce(Invoke(&write_2, &FileWrite::write)).RetiresOnSaturation();

        /* Resume the Rx cycle and stop it. */
        EXPECT_CALL(fh, read(NotNull(), FRAME_HEADER_READ_LEN)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();

        /* End TX sequence: this call orginates from on_deferred_call(). */
        FileWrite write_3(&(resp_write_byte[1]), (length_of_frame - 1u), 0);
        EXPECT_CALL(fh, write(NotNull(), (length_of_frame - 1u)))
                    .WillOnce(Invoke(&write_3, &FileWrite::write)).RetiresOnSaturation();
    } else if (current_tx_write_byte != NULL) {
ASSERT_TRUE(false);
        /* End TX sequence for the current byte in the TX pipeline: this call originates from on_deferred_call(). */
        FileWrite write(&(current_tx_write_byte[0]), current_tx_write_byte_len, 0);
        EXPECT_CALL(fh, write(NotNull(), current_tx_write_byte_len))
                    .WillOnce(Invoke(&write, &FileWrite::write)).RetiresOnSaturation();
#if 0
        mock_write = mock_free_get("write");
        CHECK(mock_write != NULL);
        mock_write->input_param[0].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->input_param[0].param        = (uint32_t)&(current_tx_write_byte[0]);
        mock_write->input_param[1].param        = current_tx_write_byte_len;
        mock_write->input_param[1].compare_type = MOCK_COMPARE_TYPE_VALUE;
        mock_write->return_value                = 0;
#endif
    } else {
        /* Resume the Rx cycle and stop it. */
        EXPECT_CALL(fh, read(NotNull(), FRAME_HEADER_READ_LEN)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();
    }

    mbed_equeue_stub::deferred_dispatch();

    delete [] file_read_hdr;
    delete [] file_read_trailer;
}


/*
 * LOOP UNTIL COMPLETE RESPONSE FRAME WRITE DONE
 * - trigger sigio callback from FileHandleMock
 * - enqueue deferred call to EventQueue
 * - CALL RETURN
 * - trigger deferred call from EventQueueMock
 * - call read
 * - call write
 * - verify completion callback state in the last iteration, if supplied
 * - write 1st byte of new pending frame in the last iteration, if supplied
 * - CALL RETURN
 */
typedef bool (*compare_func_t)();
void peer_iniated_response_tx(const uint8_t  *buf,
                              uint8_t         buf_len,
                              const uint8_t  *new_tx_byte,
                              bool            expected_state,
                              compare_func_t  func,
                              MockFileHandle &fh,
                              SigIo          &sig_io)
{
    uint8_t tx_count = 0;

    /* Write the complete response frame in do...while. */
    do {
        /* Enqueue deferred call to EventQueue.
         * Trigger sigio callback from the Filehandle used by the Mux3GPP (component under test). */
        mbed_equeue_stub::call_expect(1);
        sig_io.dispatch();

        /* Nothing to read. */
        EXPECT_CALL(fh, read(NotNull(), FRAME_HEADER_READ_LEN)).WillOnce(Return(-EAGAIN)).RetiresOnSaturation();

        FileWrite write_1(&(buf[tx_count]), (buf_len - tx_count), 1);
        EXPECT_CALL(fh, write(NotNull(), (buf_len - tx_count)))
                    .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();

        if (tx_count == (buf_len - 1)) {
            if (new_tx_byte != NULL) {
                /* Last byte of the response frame written, write 1st byte of new pending frame. */

                const uint8_t length_of_frame = 4u + (new_tx_byte[3] & ~1) + 2u; // @todo: FIX ME: magic numbers.

                FileWrite write_2(&(new_tx_byte[0]), length_of_frame, 1);
                EXPECT_CALL(fh, write(NotNull(), length_of_frame))
                            .WillOnce(Invoke(&write_2, &FileWrite::write)).RetiresOnSaturation();

                /* End TX cycle. */
                EXPECT_CALL(fh, write(NotNull(), (length_of_frame - 1u)))
                            .WillOnce(Return(0)).RetiresOnSaturation();
            }
        } else {
            /* End TX cycle. */
            EXPECT_CALL(fh, write(NotNull(), buf_len - (tx_count + 1u)))
                        .WillOnce(Return(0)).RetiresOnSaturation();
        }

        mbed_equeue_stub::deferred_dispatch();

        if (tx_count == (buf_len - 1)) {
            if (func != NULL) {
                /* Last byte of the response frame written, verify correct completion callback state. */
                EXPECT_EQ(func(), expected_state);
            }
        }

        ++tx_count;
    } while (tx_count != buf_len);
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


/*
 * TC - Ensure proper behaviour when channel is opened and multiplexer control channel open is currently running
 *
 * Test sequence:
 * - Start sending open multiplexer control channel request message, but do not finish it
 * - Issue new channel_open API call => fails with NSAPI_ERROR_IN_PROGRESS
 * - Finish sending open multiplexer control channel request message


 * - Receive open multiplexer control channel response message
 * - Send open user channel request message
 * - Receive open user channel response message
 * - Generate channel open callback with a valid FileHandle
 * - Issue new channel_open API call => accepted with NSAPI_ERROR_OK
 * - Start sending open user channel request message , but do not finish it
 * - Issue new channel_open API call => fails with NSAPI_ERROR_IN_PROGRESS
 *
 * Expected outcome:
 * - As specified above
 */
TEST_F(TestMux, channel_open_mux_open_currently_running)
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

    const uint8_t write_byte_mux_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_mux_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    /* Program TX of 1st byte of open multiplexer control channel request. */
    FileWrite write_1(&(write_byte_mux_open[0]), sizeof(write_byte_mux_open), 1);
    EXPECT_CALL(fh, write(NotNull(), SABM_FRAME_LEN))
                .WillOnce(Invoke(&write_1, &FileWrite::write)).RetiresOnSaturation();
    FileWrite write_2(&(write_byte_mux_open[1]), (sizeof(write_byte_mux_open) - 1u), 0);
    EXPECT_CALL(fh, write(NotNull(), (SABM_FRAME_LEN - 1u)))
                .WillOnce(Invoke(&write_2, &FileWrite::write)).RetiresOnSaturation();

    /* Start test sequence. */
    nsapi_error channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Issue new channel open, while previous one is still running. */
    channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_IN_PROGRESS, channel_open_err);

    /* Finish sending open multiplexer control channel request message. */

    self_iniated_request_tx(&write_byte_mux_open[1], (SABM_FRAME_LEN - 1u), FLAG_SEQUENCE_OCTET_LEN, fh, sig_io);

    /* Issue new channel open, while previous one is still running. */
    channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_IN_PROGRESS, channel_open_err);

    /* Receive open multiplexer control channel response message. */

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
    const uint32_t address_1st_channel_open = (3u) | (1u << 2);
    uint8_t write_byte_1st_channel_open[6]  =
    {
        FLAG_SEQUENCE_OCTET,
        address_1st_channel_open,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_1st_channel_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_request_rx_full_frame_tx(READ_FLAG_SEQUENCE_OCTET, STRIP_FLAG_FIELD_NO,
                                          &(read_byte[0]), sizeof(read_byte),
                                          &(write_byte_1st_channel_open[0]), sizeof(write_byte_1st_channel_open),
                                          CANCEL_TIMER_YES, START_TIMER_YES,
                                          fh, sig_io);

    /* Read the channel open response frame. */
    callback.callback_arm();
    const uint8_t read_byte_channel_open[5]  =
    {
        (3u | (1u << 2)),
        (FRAME_TYPE_UA | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte_channel_open[0], 3),
        FLAG_SEQUENCE_OCTET
    };
    self_iniated_response_rx(&(read_byte_channel_open[0]), NULL, SKIP_FLAG_SEQUENCE_OCTET, STRIP_FLAG_FIELD_NO,
                             ENQUEUE_DEFERRED_CALL_YES,
                             fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);

    /* Program TX of 1st byte of open channel request. */

    const uint32_t address_2nd_channel_open = (3u) | (2u << 2);
    uint8_t write_byte_2nd_channel_open[6]  =
    {
        FLAG_SEQUENCE_OCTET,
        address_2nd_channel_open,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_2nd_channel_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    FileWrite write_3(&(write_byte_2nd_channel_open[0]), sizeof(write_byte_2nd_channel_open), 1);
    EXPECT_CALL(fh, write(NotNull(), SABM_FRAME_LEN))
                .WillOnce(Invoke(&write_3, &FileWrite::write)).RetiresOnSaturation();
    FileWrite write_4(&(write_byte_2nd_channel_open[1]), (sizeof(write_byte_2nd_channel_open) - 1u), 0);
    EXPECT_CALL(fh, write(NotNull(), (SABM_FRAME_LEN - 1u)))
                .WillOnce(Invoke(&write_4, &FileWrite::write)).RetiresOnSaturation();

    /* Start test sequence. */
    channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Issue new channel open, while previous one is still running. */
    channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_IN_PROGRESS, channel_open_err);
}


/*
 * TC - Ensure proper behaviour when multiplexer control channel open is requested and DM TX is currently running
 *
 * Test sequence:
 * - Receive DISC command to DLCI 0
 * - Start sending DM response message, but do not finish it
 * - Issue channel_open API call => accepted with NSAPI_ERROR_OK
 * -- operation set as pending, as TX DM allready inprogress
 * - Issue new channel_open API call => fails with NSAPI_ERROR_IN_PROGRESS
 * - Finish sending DM response message
 * - Start sending pending open multiplexer control channel request message
 * - Receive open multiplexer control channel response message
 * - Send open user channel request message
 * - Receive open user channel response message
 * - Generate channel open callback with a valid FileHandle
 *
 * Expected outcome:
 * - As specified above
 */
TEST_F(TestMux, mux_open_dm_tx_currently_running)
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

    const uint8_t dlci_id      = 0;
    const uint8_t read_byte[6] =
    {
        FLAG_SEQUENCE_OCTET,
        /* Peer assumes the role of initiator. */
        3u | (dlci_id << 2),
        (FRAME_TYPE_DISC | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    /* Generate DISC from peer and trigger TX of DM response, do not finish it. */

    const uint8_t write_byte_dm[6] =
    {
        FLAG_SEQUENCE_OCTET,
        3u | (dlci_id << 2),
        (FRAME_TYPE_DM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_dm[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_request_rx(&(read_byte[0]), READ_FLAG_SEQUENCE_OCTET, &(write_byte_dm[0]), NULL, 0, fh, sig_io);

    /* Issue channel_open API call, operation set as pending, as TX DM allready inprogress. */

    /* Start test sequence. */
    nsapi_error channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Issue new channel open, while pending exists. */

    channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_IN_PROGRESS, channel_open_err);

    /* Finish sending DM response message and start TX of 1st byte of the pending open multiplexer control channel
     * request message. */

    const uint8_t write_byte_mux_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_mux_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_response_tx(&(write_byte_dm[1]),
                             (DM_FRAME_LEN -1u),
                             &(write_byte_mux_open[0]),
                             false,
                             NULL,
                             fh,
                             sig_io);

    /* Finish sending open multiplexer control channel request message, receive open multiplexer control channel
     * response message, which starts the user channel creation procedure. */

    const uint8_t read_byte_mux_open[5] =
    {
        ADDRESS_MUX_START_RESP_OCTET,
        (FRAME_TYPE_UA | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte_mux_open[0], 3),
        FLAG_SEQUENCE_OCTET
    };
    self_iniated_request_tx(&(write_byte_mux_open[1]),
                            (sizeof(write_byte_mux_open) - sizeof(write_byte_mux_open[0])),
                            FRAME_HEADER_READ_LEN,
                            fh,
                            sig_io);

    const uint32_t address_1st_channel_open = (3u) | (1u << 2);
    uint8_t write_byte_1st_channel_open[6]  =
    {
        FLAG_SEQUENCE_OCTET,
        address_1st_channel_open,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_1st_channel_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_request_rx_full_frame_tx(SKIP_FLAG_SEQUENCE_OCTET, STRIP_FLAG_FIELD_NO,
                                          &(read_byte_mux_open[0]), sizeof(read_byte_mux_open),
                                          &(write_byte_1st_channel_open[0]), sizeof(write_byte_1st_channel_open),
                                          CANCEL_TIMER_YES, START_TIMER_YES,
                                          fh, sig_io);

    /* Receive open user channel response message. */

    callback.callback_arm();
    const uint8_t read_byte_channel_open[5]  =
    {
        (3u | (1u << 2)),
        (FRAME_TYPE_UA | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte_channel_open[0], 3),
        FLAG_SEQUENCE_OCTET
    };
    self_iniated_response_rx(&(read_byte_channel_open[0]),
                             NULL,
                             SKIP_FLAG_SEQUENCE_OCTET,
                             STRIP_FLAG_FIELD_NO,
                             ENQUEUE_DEFERRED_CALL_YES,
                             fh,
                             sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);
}


void mux_self_iniated_open_rx_frame_sync_done(MuxCallbackTest &callback,
                                              uint8_t          frame_type,
                                              mbed::Mux3GPP   &mux,
                                              MockFileHandle  &fh,
                                              SigIo           &sig_io)
{
    mux_self_iniated_open(FRAME_HEADER_READ_LEN,
                          SKIP_FLAG_SEQUENCE_OCTET,
                          STRIP_FLAG_FIELD_YES,
                          callback,
                          frame_type,
                          mux,
                          fh,
                          sig_io);
}


/*
 * TC - Ensure proper behaviour when multiplexer control channel open request is rejected by the peer
 *
 * Test sequence:
 * - Send open multiplexer control channel request message
 * - Peer rejects open multiplexer control channel request message with appropriate response message
 * - Send open multiplexer control channel request message
 * - Receive open multiplexer control channel response message
 * - Send open user channel request message
 * - Receive open user channel response message
 * - Generate channel open callback with a valid FileHandle
 *
 * Expected outcome:
 * - As specified above
 */
TEST_F(TestMux, channel_open_mux_open_rejected_by_peer)
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

    const uint8_t write_byte_mux_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_mux_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    FileWrite write(&(write_byte_mux_open[0]), sizeof(write_byte_mux_open), 1);
    EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open)))
                .WillOnce(Invoke(&write, &FileWrite::write)).RetiresOnSaturation();
    /* End TX cycle. */
    EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open) - sizeof(write_byte_mux_open[0])))
                .WillOnce(Return(0)).RetiresOnSaturation();

    /* Start test sequence. Test set mocks. */
    const nsapi_error channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Finish the frame write sequence. */
    self_iniated_request_tx(&(write_byte_mux_open[1]), (SABM_FRAME_LEN - 1u), FLAG_SEQUENCE_OCTET_LEN, fh, sig_io);

    /* Peer rejects open multiplexer control channel request message with appropriate response message. */

    const uint8_t read_byte_mux_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_RESP_OCTET,
        (FRAME_TYPE_DM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte_mux_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };
    callback.callback_arm();
    self_iniated_response_rx(&(read_byte_mux_open[0]),
                             NULL,
                             READ_FLAG_SEQUENCE_OCTET,
                             STRIP_FLAG_FIELD_NO,
                             ENQUEUE_DEFERRED_CALL_YES,
                             fh,
                             sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_EQ(NULL, callback.file_handle_get());

    /* Open multiplexer control channel and user channel. */

    mux_self_iniated_open_rx_frame_sync_done(callback, FRAME_TYPE_UA, obj, fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);
}


/*
 * TC - Ensure proper behaviour when multiplexer control channel open request timeouts
 *
 * Test sequence:
 * - Send open multiplexer control channel request message
 * - Generate maxium amount of timeout events, which trigger retransmission of open multiplexer control channel request
 *   message
 * - Once maxium retransmission limit reached, complete operation with failure to the user
 * - Do a successfull channel open procedure
 *
 * Expected outcome:
 * - As specified above
 */
TEST_F(TestMux, channel_open_mux_open_success_after_timeout)
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

    const uint8_t write_byte_mux_open[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&write_byte_mux_open[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    FileWrite write(&(write_byte_mux_open[0]), sizeof(write_byte_mux_open), 1);
    EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open)))
                .WillOnce(Invoke(&write, &FileWrite::write)).RetiresOnSaturation();
    /* End TX cycle. */
    EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open) - sizeof(write_byte_mux_open[0])))
                .WillOnce(Return(0)).RetiresOnSaturation();

    /* Start test sequence. Test set mocks. */
    const nsapi_error channel_open_err = obj.channel_open();
    EXPECT_EQ(NSAPI_ERROR_OK, channel_open_err);

    /* Generate maxium amount of timeout events, which trigger retransmission of open multiplexer control channel
       request message. */

    /* Complete the frame write. */
    self_iniated_request_tx(&(write_byte_mux_open[1]), (SABM_FRAME_LEN - 1u), FLAG_SEQUENCE_OCTET_LEN, fh, sig_io);

    /* Begin frame re-transmit sequence.*/
    uint8_t counter = RETRANSMIT_COUNT;
    do {
        FileWrite write(&(write_byte_mux_open[0]), sizeof(write_byte_mux_open), 1);
        EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open)))
                    .WillOnce(Invoke(&write, &FileWrite::write)).RetiresOnSaturation();
        /* End TX cycle. */
        EXPECT_CALL(fh, write(NotNull(), sizeof(write_byte_mux_open) - sizeof(write_byte_mux_open[0])))
                    .WillOnce(Return(0)).RetiresOnSaturation();

        /* Trigger timer timeout. */
        mbed_equeue_stub::timer_dispatch();

        /* Re-transmit the complete remaining part of the frame. */
        self_iniated_request_tx(&(write_byte_mux_open[1]), (SABM_FRAME_LEN - 1u), FLAG_SEQUENCE_OCTET_LEN, fh, sig_io);

        --counter;
    } while (counter != 0);

    /* Trigger timer to finish the re-transmission cycle and the whole open multiplexer control channel request. */
    callback.callback_arm();
    mbed_equeue_stub::timer_dispatch();

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_EQ(NULL, callback.file_handle_get());

    /* Open multiplexer control channel and user channel. */

    mux_self_iniated_open(callback, FRAME_TYPE_UA, obj, fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);
}


/*
 * TC - Ensure proper behaviour when multiplexer control channel open request is recieved from the peer
 *
 * Test sequence:
 * - Receive open multiplexer control channel request message
 *
 * Expected outcome:
 * - No action taken by the implementation: received open multiplexer control channel request message silently discarded
 */
TEST_F(TestMux,  mux_open_peer_initiated)
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

    const uint8_t read_byte[6] =
    {
        FLAG_SEQUENCE_OCTET,
        ADDRESS_MUX_START_REQ_OCTET,
        (FRAME_TYPE_SABM | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte[1], 3),
        FLAG_SEQUENCE_OCTET
    };

    peer_iniated_request_rx(&(read_byte[0]), READ_FLAG_SEQUENCE_OCTET, NULL, NULL, 0, fh, sig_io);
}


/*
 * TC - Ensure proper behaviour when multiplexer is open and peer sends DISC command to DLCI 0
 *
 * Test sequence:
 * - Establish a user channel
 * - Receive DISC command to DLCI 0 from the peer
 *
 * Expected outcome:
 * - No action taken by the implementation: received DISC command is silently discarded
 */
TEST_F(TestMux, mux_open_rx_disc_dlci_0)
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

    /* Open multiplexer control channel and user channel. */

    mux_self_iniated_open(callback, FRAME_TYPE_UA, obj, fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);

    /* Generate DISC from peer which is ignored by the implementation. */

    const uint8_t dlci_id      = 0;
    const uint8_t read_byte[5] =
    {
        /* Peer assumes the role of the responder. */
        1u | (dlci_id << 2),
        (FRAME_TYPE_DISC | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte[0], 3u),
        FLAG_SEQUENCE_OCTET
    };
    peer_iniated_request_rx(&(read_byte[0]), SKIP_FLAG_SEQUENCE_OCTET, NULL, NULL, 0, fh, sig_io);
}


/*
 * TC - Ensure proper behaviour when peer sends DISC command to established user channel ID
 *
 * Test sequence:
 * - Establish a user channel
 * - Receive DISC command to the established user channel ID from the peer
 *
 * Expected outcome:
 * - No action taken by the implementation: received DISC command is silently discarded
 */
TEST_F(TestMux, mux_open_rx_disc_dlci_in_use)
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


    /* Open multiplexer control channel and user channel. */

    mux_self_iniated_open(callback, FRAME_TYPE_UA, obj, fh, sig_io);

    /* Validate Filehandle generation. */
    EXPECT_TRUE(callback.is_callback_called());
    EXPECT_TRUE(callback.file_handle_get() != NULL);

    const uint8_t read_byte[5] =
    {
        /* Peer assumes the role of the responder. */
        1u | (1u << 2),
        (FRAME_TYPE_DISC | PF_BIT),
        LENGTH_INDICATOR_OCTET,
        fcs_calculate(&read_byte[0], 3u),
        FLAG_SEQUENCE_OCTET
    };
    /* Generate DISC from peer which is ignored buy the implementation. */
    peer_iniated_request_rx(&(read_byte[0]), SKIP_FLAG_SEQUENCE_OCTET, NULL, NULL, 0, fh, sig_io);
}
