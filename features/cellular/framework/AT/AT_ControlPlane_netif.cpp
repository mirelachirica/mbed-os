/*AT_ControlPlane_netif.cpp*/
#include "AT_ControlPlane_netif.h"

namespace mbed {

AT_ControlPlane_netif::AT_ControlPlane_netif(ATHandler &at, int cid) : AT_CellularBase(at),
    _cid(cid), _cb(NULL), _data(NULL)
{
    _recv_buffer = new char[MAX_CP_DATA_RECV_LEN];
    _recv_len = 0;

    // TODO: Add this only when _cp_in_use
    _at.set_urc_handler("+CRTDCP:", mbed::Callback<void()>(this, &AT_ControlPlane_netif::urc_cp_recv));
}

AT_ControlPlane_netif::~AT_ControlPlane_netif()
{
    if (_recv_buffer) {
        delete[] _recv_buffer;
        _recv_buffer = NULL;
    }
}

void AT_ControlPlane_netif::urc_cp_recv()
{
    //+CRTDCP: <cid>,<cpdata_length>,<cpdata>
    _at.lock();
    int cid = _at.read_int();
    int cpdata_length = _at.read_int();

    char cpdata[MAX_CP_DATA_RECV_LEN];
    int read_len = _at.read_string(cpdata, sizeof(cpdata));

    _at.unlock();

    // cid not expected to be different because: one context - one file handle
    // so this file handle cannot get urc from different context
    if (read_len > 0 && read_len == cpdata_length && cid == _cid) {
        data_received(cpdata, (nsapi_size_t)read_len);
    }
}

nsapi_size_or_error_t AT_ControlPlane_netif::send(const void *cpdata, nsapi_size_t cpdata_length)
{
    //CSODCP
    _at.lock();
    _at.cmd_start("AT+CSODCP=");
    _at.write_int(_cid);
    _at.write_int(cpdata_length);
    _at.write_bytes((uint8_t *)cpdata, cpdata_length);

    return _at.unlock_return_error();
}

nsapi_size_or_error_t AT_ControlPlane_netif::recv(void *cpdata, nsapi_size_t cpdata_length)
{
    // If no data received through CRTDCP URC
    if (!_recv_len) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    // If too small buffer for data
    if (_recv_len > cpdata_length) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    memcpy(cpdata, _recv_buffer, _recv_len);

    return _recv_len = 0;
}

void AT_ControlPlane_netif::attach(void (*callback)(void *), void *data)
{
    _cb = callback;
    _data = data;
}

void AT_ControlPlane_netif::data_received(char* buffer, nsapi_size_t size)
{
    if (buffer && size && size <= sizeof(_recv_buffer)) {
        memcpy(_recv_buffer, buffer, size);
        _recv_len = size;
    }

    // call socket event
    if (!_cb) {
        return;
    }
    _cb(_data);
}

} //mbed namespace
