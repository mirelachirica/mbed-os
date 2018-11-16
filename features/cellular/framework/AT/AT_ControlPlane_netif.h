#include "ControlPlane_netif.h"
#include "ATHandler.h"
#include "AT_CellularBase.h"

namespace mbed {

class AT_ControlPlane_netif: public ControlPlane_netif, public AT_CellularBase {
public:
    AT_ControlPlane_netif(ATHandler &at, int cid);
    virtual ~AT_ControlPlane_netif();

    virtual nsapi_error_t send(const void *data, nsapi_size_t size);
    virtual nsapi_error_t recv(void *buffer, nsapi_size_t size);


/** Register a callback on state change of the socket
 *
 *  The specified callback will be called on state changes such as when
 *  the socket can recv/send successfully and on when an error
 *  occurs. The callback may also be called spuriously without reason.
 *
 *  The callback may be called in an interrupt context and should not
 *  perform expensive operations such as recv/send calls.
 *
 *  @param handle   Socket handle
 *  @param callback Function to call on state change
 *  @param data     Argument to pass to callback
 */

    virtual void attach(void (*callback)(void *), void *data);

    virtual void data_received(char* buffer = NULL, nsapi_size_t size = 0);

    void (*_cb)(void *);
    void *_data;

    char *_recv_buffer;
    size_t _recv_len;
};

} //mbed namespace
