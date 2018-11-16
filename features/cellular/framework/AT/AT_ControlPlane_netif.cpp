/*AT_ControlPlane_netif.cpp*/
#include "AT_ControlPlane_netif.h"

namespace mbed {

AT_ControlPlane_netif::AT_ControlPlane_netif(ATHandler &at, int cid) : AT_CellularBase(at)
{
    _cid = cid;
    _cb = NULL;
    _data = NULL;
    _recv_buffer = NULL;
    _recv_len = 0;
}

AT_ControlPlane_netif::~AT_ControlPlane_netif()
{
}

nsapi_error_t AT_ControlPlane_netif::send(const void *data, nsapi_size_t size){
    //CSODCP
    return NSAPI_ERROR_OK;
}

nsapi_error_t AT_ControlPlane_netif::recv(void *buffer, nsapi_size_t size){
    //CRTDCP

    // urc should set received data and length to members
    // and this call should return them and then reset them
    // or WOULD_BLOCK if they are not set

    return NSAPI_ERROR_OK;
}

void AT_ControlPlane_netif::attach(void (*callback)(void *), void *data)
{
    _cb = callback;
    _data = data;
}

void AT_ControlPlane_netif::data_received(char* buffer, nsapi_size_t size)
{
    _recv_buffer = buffer;
    _recv_len = size;

    // call socket event
    if (!_cb) {
        return;
    }
    _cb(_data);
}

} //mbed namespace
