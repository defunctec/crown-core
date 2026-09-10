// Copyright (c) 2026 The Crown developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcprotocol.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(rpcprotocol_tests)

BOOST_AUTO_TEST_CASE(ssliostreamdevice_connect_uses_stream_context)
{
    boost::asio::io_context ioContext;
    boost::asio::ssl::context sslContext(boost::asio::ssl::context::sslv23);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sslStream(ioContext, sslContext);
    SSLIOStreamDevice<boost::asio::ip::tcp> device(sslStream, false);

    boost::asio::ip::tcp::acceptor acceptor(
        ioContext,
        boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    boost::asio::ip::tcp::socket peer(ioContext);

    boost::system::error_code acceptError;
    acceptor.async_accept(peer, [&acceptError](const boost::system::error_code& ec) {
        acceptError = ec;
    });

    BOOST_CHECK(device.connect("127.0.0.1", boost::lexical_cast<std::string>(acceptor.local_endpoint().port())));
    ioContext.poll();
    BOOST_CHECK(!acceptError);

    sslStream.lowest_layer().close();
    peer.close();
    acceptor.close();
}

BOOST_AUTO_TEST_SUITE_END()
