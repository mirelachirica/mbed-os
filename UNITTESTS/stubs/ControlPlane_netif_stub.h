#include "netsocket/cellular/ControlPlane_netif.h"
#include <list>

namespace mbed {

class ControlPlane_netif_stub : public ControlPlane_netif {
public:
    std::list<nsapi_error_t> return_values;
    nsapi_error_t return_value;

    ControlPlane_netif_stub()
    {
        return_value = 0;
    }

protected:
    virtual nsapi_error_t send(const void *cpdata, nsapi_size_t cpdata_length)
    {
        if (return_value == NSAPI_ERROR_OK && return_values.front() == NSAPI_ERROR_OK) {
        }
        return return_value;
    };
    virtual nsapi_error_t recv(void *cpdata, nsapi_size_t cpdata_length)
    {
        return return_value;
    };
    virtual void data_received()
    {};
    virtual void attach(void (*callback)(void *), void *data) {};
};

}
