#include "QUECTEL_BG96_ControlPlane_netif.h"

namespace mbed {

QUECTEL_BG96_ControlPlane_netif::QUECTEL_BG96_ControlPlane_netif(ATHandler &at, int cid) : AT_ControlPlane_netif(at, cid)
{
    _cid = cid;
}

nsapi_error_t QUECTEL_BG96_ControlPlane_netif::send(const void *data, nsapi_size_t size)
{
    // AT+QCFGEXT="nipds"
    return NSAPI_ERROR_OK;
}

nsapi_error_t QUECTEL_BG96_ControlPlane_netif::recv(void *buffer, nsapi_size_t size)
{
    _at.cmd_start("AT+QCFGEXT=\"nipdr\",");
    _at.write_int(size);
    _at.cmd_stop();

    _at.resp_start("+QCFGEXT:");
    // skip "nipdr"
    _at.skip_param();
    int read_length = _at.read_int();
    if (!read_length) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    _at.read_string((char*)buffer, read_length);
    _at.resp_stop();


    // AT+QCFGEXT="nipdr" -> WOULD_BLOCK if no data
    return NSAPI_ERROR_OK;
}

} // mbed namespace
