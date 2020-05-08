#include "WebsocketClient.h"
#include "Log.h"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;
namespace net = boost::asio;    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

crust::Log *p_log = crust::Log::get_instance();

bool WebsocketClient::websocket_init(std::string host, std::string port, std::string route)
{
    try
    {
        // The io_context is required for all I/O
        net::io_context ioc;

        // The SSL context is required, and holds certificates
        ssl::context ctx{ssl::context::tlsv12_client};

        // This holds the root certificate used for verification
        load_root_certificates(ctx);

        // These objects perform our I/O
        tcp::resolver resolver{ioc};
        websocket::stream<beast::ssl_stream<tcp::socket>> ws{ioc, ctx};

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        net::connect(ws.next_layer().next_layer(), results.begin(), results.end());

        // Perform the SSL handshake
        ws.next_layer().handshake(ssl::stream_base::client);

        // Set a decorator to change the User-Agent of the handshake
        ws.set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req)
            {
                req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
            }));

        // Perform the websocket handshake
        ws.handshake(host, route);

        this->_ws = &ws;
    }
    catch(std::exception const& e)
    {
        p_log->err("Initialize websocket client failed! Error: %s\n", e.what());
        return false;
    }

    return true;
}

bool WebsocketClient::websocket_request(std::string content, std::string &res)
{
    if (this->_ws == NULL)
    {
        p_log->err("Websocket request failed! Please initialize websocket first!\n");
        return false;
    }

    try
    {
        // Send the message
        this->_ws->write(net::buffer(content));

        // This buffer will hold the incoming message
        beast::flat_buffer buffer;

        // Read a message into our buffer
        this->_ws->read(buffer);

        res = beast::buffers_to_string(buffer.data());
    }
    catch(std::exception const& e)
    {
        p_log->err("Send websocket request failed! Error: %s\n", e.what());
        return false;
    }

    return true;
}

void WebsocketClient::websocket_close()
{
    // Close the WebSocket connection
    this->_ws->close(websocket::close_code::normal);
    this->_ws = NULL;
}
