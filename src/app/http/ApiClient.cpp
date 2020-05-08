#include "ApiClient.h"
#include "Common.h"
#include "Config.h"
#include "Log.h"


namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace net = boost::asio;    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

crust::Log *p_log = crust::Log::get_instance();

int ApiClient::Get(std::string url)
{
    return request_sync(http::verb::get, url, "", NULL);
}

int ApiClient::Get(std::string url, std::string body)
{
    return request_sync(http::verb::get, url, body, NULL);
}

int ApiClient::Get(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync(http::verb::get, url, body, &headers);
}

int ApiClient::SSLGet(std::string url)
{
    return request_sync_ssl(http::verb::get, url, "", NULL);
}

int ApiClient::SSLGet(std::string url, std::string body)
{
    return request_sync_ssl(http::verb::get, url, body, NULL);
}

int ApiClient::SSLGet(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::get, url, body, &headers);
}

int ApiClient::Post(std::string url)
{
    return request_sync(http::verb::post, url, "", NULL);
}

int ApiClient::Post(std::string url, std::string body)
{
    return request_sync(http::verb::post, url, body, NULL);
}

int ApiClient::Post(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync(http::verb::post, url, body, &headers);
}

int ApiClient::SSLPost(std::string url)
{
    return request_sync_ssl(http::verb::post, url, "", NULL);
}

int ApiClient::SSLPost(std::string url, std::string body)
{
    return request_sync_ssl(http::verb::post, url, body, NULL);
}

int ApiClient::SSLPost(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::post, url, body, &headers);
}

// Performs an HTTP GET and prints the response
int ApiClient::request_sync_ssl(http::verb method, std::string url, std::string body, ApiHeaders *headers)
{
    try
    {
        UrlEndPoint *url_end_point = get_url_end_point(url);
        auto const host = url_end_point->ip.c_str();
        auto const port = std::to_string(url_end_point->port).c_str();
        auto const path = url_end_point->base.c_str();
        int version = 10;
        //int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        tcp::resolver resolver(ioc);

        // The SSL context is required, and holds certificates
        ssl::context ctx(ssl::context::tlsv12_client);

        // This holds the root certificate used for verification
        load_root_certificates(ctx);

        // Verify the remote server's certificate
        ctx.set_verify_mode(ssl::verify_peer);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(! SSL_set_tlsext_host_name(stream.native_handle(), const_cast<char*>(host)))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream).connect(results);

        // Perform the SSL handshake
        stream.handshake(ssl::stream_base::client);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{method, path, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        // Set header
        for (auto entry = headers->begin(); entry != headers->end(); entry++)
        {
            req.set(entry->first, entry->second);
        }
        // Set body
        req.body() = body;

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to standard out
        std::cout << res << std::endl;

        // Gracefully close the stream
        beast::error_code ec;
        stream.shutdown(ec);
        if(ec == net::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec = {};
        }
        if(ec)
            throw beast::system_error{ec};

        // If we get here then the connection is closed gracefully
    }
    catch(std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int ApiClient::request_sync(http::verb method, std::string url, std::string body, ApiHeaders *headers)
{
    try
    {
        UrlEndPoint *url_end_point = get_url_end_point(url);
        auto const host = url_end_point->ip.c_str();
        auto const port = std::to_string(url_end_point->port).c_str();
        auto const path = url_end_point->base.c_str();
        int version = 10;

        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        stream.connect(results);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{method, path, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        // Set header
        for (auto entry = headers->begin(); entry != headers->end(); entry++)
        {
            req.set(entry->first, entry->second);
        }
        // Set body
        req.body() = body;

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to standard out
        std::cout << res << std::endl;

        // Gracefully close the socket
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        // not_connected happens sometimes
        // so don't bother reporting it.
        //
        if(ec && ec != beast::errc::not_connected)
            throw beast::system_error{ec};

        // If we get here then the connection is closed gracefully
    }
    catch(std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
