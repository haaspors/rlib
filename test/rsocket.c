#include <rlib/rlib.h>

RTEST (rsocket, new_close, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;

  r_assert_cmpptr (r_socket_new (R_SOCKET_FAMILY_NONE,
          R_SOCKET_TYPE_NONE, R_SOCKET_PROTOCOL_DEFAULT), ==, NULL);
  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert (r_socket_is_alive (socket));
  r_assert (!r_socket_is_connected (socket));

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_assert (r_socket_is_closed (socket));
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, bind, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;
  RSocketAddress * addr;

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);

  r_assert_cmpint (r_socket_bind (socket, NULL, FALSE), ==, R_SOCKET_INVAL);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (255, 0, 0, 255, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_ERROR);
  r_socket_address_unref (addr);

#ifdef R_OS_UNIX
  /* FIXME: There might be systems that allow you to bind to known services port */
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 80)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_ERROR);
  r_socket_address_unref (addr);
#endif

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, get_local_address, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;
  RSocketAddress * addr;

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);

#ifdef R_OS_UNIX
  r_assert_cmpptr ((addr = r_socket_get_local_address (socket)), !=, NULL);
  r_assert_cmphex (r_socket_address_ipv4_get_port (addr), ==, 0);
  r_assert_cmphex (r_socket_address_ipv4_get_ip (addr), ==, 0);
  r_socket_address_unref (addr);
#endif

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);

  r_assert_cmpptr ((addr = r_socket_get_local_address (socket)), !=, NULL);
  r_assert_cmphex (r_socket_address_ipv4_get_port (addr), ==, 0x4242);
  r_assert_cmphex (r_socket_address_ipv4_get_ip (addr), ==, 0x7f000001);
  r_socket_address_unref (addr);

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, listen, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;
  RSocketAddress * addr;

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert (!r_socket_is_listening (socket));

  /* wrong socket type */
  r_assert_cmpint (r_socket_listen (socket), ==, R_SOCKET_INVALID_OP);
  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);

#if 0
  /* Socket is bound to 0.0.0.0 and some port by default... */
  r_assert_cmpint (r_socket_listen (socket), ==, R_SOCKET_NOT_BOUND);
#endif

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_socket_listen (socket), ==, R_SOCKET_OK);
  r_assert (r_socket_is_listening (socket));

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, connect_would_block, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;
  RSocketAddress * addr;

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);

  r_assert (!r_socket_is_connecting (socket));
  r_assert (!r_socket_is_connected (socket));

  r_assert_cmpint (r_socket_connect (socket, NULL), ==, R_SOCKET_INVAL);

  /* Sockets should be created in non-blocking mode, so this should block! */
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  /* FIXME: This might actually connect with OK on some systems... */
  r_assert_cmpint (r_socket_connect (socket, addr), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);
  r_assert (r_socket_is_connecting (socket));
  r_assert (!r_socket_is_connected (socket));

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, accept, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * socket;
  RSocketAddress * addr;
  RSocketStatus res;

  r_assert_cmpptr ((socket = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (socket, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);

  r_assert_cmpint (r_socket_listen (socket), ==, R_SOCKET_OK);
  /* Sockets should be created in non-blocking mode, so this should block! */
  r_assert_cmpptr (r_socket_accept (socket, &res), ==, NULL);
  r_assert_cmpint (res, ==, R_SOCKET_WOULD_BLOCK);

  r_assert_cmpint (r_socket_close (socket), ==, R_SOCKET_OK);
  r_socket_unref (socket);
}
RTEST_END;

RTEST (rsocket, shutdown, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * consock, * lissock, * asock;
  RSocketAddress * addr;

  r_assert_cmpptr ((consock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((lissock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);

  r_assert_cmpint (r_socket_shutdown (consock, FALSE, FALSE), ==, R_SOCKET_INVAL);
  r_assert_cmpint (r_socket_shutdown (consock, TRUE, TRUE), ==, R_SOCKET_NOT_CONNECTED);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (lissock, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (lissock), ==, R_SOCKET_OK);

  r_assert_cmpint (r_socket_connect (consock, addr), ==, R_SOCKET_WOULD_BLOCK);
  r_assert (r_socket_set_blocking (lissock, TRUE));
  r_assert_cmpptr ((asock = r_socket_accept (lissock, NULL)), !=, NULL);
  r_assert_cmpint (r_socket_close (lissock), ==, R_SOCKET_OK);
  r_socket_unref (lissock);
  r_socket_address_unref (addr);

  r_assert_cmpint (r_socket_shutdown (asock, TRUE, FALSE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_shutdown (consock, TRUE, TRUE), ==, R_SOCKET_OK);

  r_assert_cmpint (r_socket_close (consock), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_close (asock), ==, R_SOCKET_OK);
  r_socket_unref (consock);
  r_socket_unref (asock);
}
RTEST_END;

static rpointer
rsocket_test_accept (rpointer data)
{
  RSocket * s = data;
  return r_socket_accept (s, NULL);
}

RTEST (rsocket, listen_connect_accept, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * consock, * lissock, * asock;
  RSocketAddress * addr;
  RThread * accept_thread;

  r_assert_cmpptr ((lissock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((consock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert (r_socket_set_blocking (lissock, TRUE));
  r_assert (r_socket_set_blocking (consock, TRUE));

  r_assert (r_socket_is_alive (consock));
  r_assert (r_socket_is_alive (consock));
  r_assert (!r_socket_is_connected (consock));
  r_assert_cmpptr ((addr = r_socket_get_remote_address (lissock)), ==, NULL);
  r_assert_cmpptr ((addr = r_socket_get_remote_address (consock)), ==, NULL);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (lissock, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (lissock), ==, R_SOCKET_OK);

  r_assert_cmpptr ((accept_thread = r_thread_new (NULL, rsocket_test_accept, lissock)), !=, NULL);
  r_assert_cmpint (r_socket_connect (consock, addr), ==, R_SOCKET_OK);

  r_assert_cmpptr ((asock = r_thread_join (accept_thread)), !=, NULL);
  r_thread_unref (accept_thread);
  r_assert_cmpint (r_socket_close (lissock), ==, R_SOCKET_OK);
  r_socket_unref (lissock);

  r_assert (r_socket_is_connected (consock));
  r_assert (r_socket_is_connected (asock));

  /* FIXME: check local vs remote, asock vs consock*/
  r_socket_address_unref (addr);

  r_assert_cmpint (r_socket_close (asock), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_close (consock), ==, R_SOCKET_OK);
  r_socket_unref (asock);
  r_socket_unref (consock);
}
RTEST_END;

RTEST (rsocket, send_recv, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * consock, * lissock, * asock;
  RSocketAddress * addr;

  r_assert_cmpptr ((consock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((lissock = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);

  r_assert_cmpint (r_socket_shutdown (consock, FALSE, FALSE), ==, R_SOCKET_INVAL);
  r_assert_cmpint (r_socket_shutdown (consock, TRUE, TRUE), ==, R_SOCKET_NOT_CONNECTED);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpint (r_socket_bind (lissock, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (lissock), ==, R_SOCKET_OK);

  r_assert_cmpint (r_socket_connect (consock, addr), ==, R_SOCKET_WOULD_BLOCK);
  r_assert (r_socket_set_blocking (lissock, TRUE));
  r_assert_cmpptr ((asock = r_socket_accept (lissock, NULL)), !=, NULL);
  r_assert_cmpint (r_socket_close (lissock), ==, R_SOCKET_OK);
  r_socket_unref (lissock);
  r_socket_address_unref (addr);

  /* Send and recv */
  {
    ruint8 txbuf[512], rxbuf[512];
    rsize size = 0;
    r_memset (txbuf, 0x42, 512);
    r_memset (rxbuf, 0x00, 512);

    r_assert (r_socket_set_blocking (consock, TRUE));
    r_assert (r_socket_set_blocking (asock, TRUE));

    r_assert_cmpint (r_socket_send (asock, txbuf, 512, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 512);
    r_assert_cmpint (r_socket_receive (consock, rxbuf, 512, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 512);

    r_assert_cmpmem (txbuf, ==, rxbuf, 512);
  }

  r_assert_cmpint (r_socket_close (consock), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_close (asock), ==, R_SOCKET_OK);
  r_socket_unref (consock);
  r_socket_unref (asock);
}
RTEST_END;

RTEST (rsocket, sendto_recvfrom, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * sock1, * sock2;
  RSocketAddress * addr1, * addr2, * srcaddr;

  r_assert_cmpptr ((sock1 = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert_cmpptr ((sock2 = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);

  r_assert_cmpptr ((addr1 = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpptr ((addr2 = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x2222)), !=, NULL);
  r_assert_cmpptr ((srcaddr = r_socket_address_new ()), !=, NULL);
  r_assert_cmpint (r_socket_bind (sock1, addr1, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_bind (sock2, addr2, TRUE), ==, R_SOCKET_OK);

  /* sendto and recvfrom */
  {
    ruint8 txbuf[512], rxbuf[512];
    rsize size = 0;
    r_memset (txbuf, 0x42, 512);
    r_memset (rxbuf, 0x00, 512);

    r_assert (r_socket_set_blocking (sock1, TRUE));
    r_assert (r_socket_set_blocking (sock2, TRUE));

    r_assert_cmpint (r_socket_send_to (sock1, addr2, txbuf, 512, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 512);
    r_assert_cmpint (r_socket_receive_from (sock2, srcaddr, rxbuf, 512, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 512);

    r_assert (r_socket_address_is_equal (srcaddr, addr1));
    r_assert_cmpmem (txbuf, ==, rxbuf, 512);
  }

  r_assert_cmpint (r_socket_close (sock1), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_close (sock2), ==, R_SOCKET_OK);
  r_socket_unref (sock1);
  r_socket_unref (sock2);
  r_socket_address_unref (addr1);
  r_socket_address_unref (addr2);
  r_socket_address_unref (srcaddr);
}
RTEST_END;

RTEST (rsocket, sendmsg_recvmsg, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * sock1, * sock2;
  RSocketAddress * addr1, * addr2, * srcaddr;

  r_assert_cmpptr ((sock1 = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert_cmpptr ((sock2 = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);

  r_assert_cmpptr ((addr1 = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert_cmpptr ((addr2 = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x2222)), !=, NULL);
  r_assert_cmpptr ((srcaddr = r_socket_address_new ()), !=, NULL);
  r_assert_cmpint (r_socket_bind (sock1, addr1, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_bind (sock2, addr2, TRUE), ==, R_SOCKET_OK);

  /* sendmsg and recvmsg */
  {
    ruint8 txbuf[2][512];
    RBuffer * buf1, * buf2;
    RMem * mem;
    rsize size = 0;
    r_memset (txbuf[0], 0x42, 512);
    r_memset (txbuf[1], 0x22, 512);

    r_assert_cmpptr ((buf1 = r_buffer_new ()), !=, NULL);
    r_assert_cmpptr ((mem = r_mem_new_wrapped (R_MEM_FLAG_NONE, txbuf[0], 512, 256, 128, NULL, NULL)), !=, NULL);
    r_assert (r_buffer_mem_append (buf1, mem));
    r_mem_unref (mem);
    r_assert_cmpptr ((mem = r_mem_new_wrapped (R_MEM_FLAG_NONE, txbuf[1], 512, 512, 0, NULL, NULL)), !=, NULL);
    r_assert (r_buffer_mem_append (buf1, mem));
    r_mem_unref (mem);
    r_assert_cmpptr ((buf2 = r_buffer_new_take (r_malloc (1024), 1024)), !=, NULL);

    r_assert (r_socket_set_blocking (sock1, TRUE));
    r_assert (r_socket_set_blocking (sock2, TRUE));

    r_assert_cmpint (r_socket_send_message (sock1, addr2, buf1, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 768);
    r_assert_cmpint (r_socket_receive_message (sock2, srcaddr, buf2, &size), ==, R_SOCKET_OK);
    r_assert_cmpuint (size, ==, 768);
    r_assert_cmpuint (r_buffer_get_size (buf2), ==, size);

    r_assert (r_socket_address_is_equal (srcaddr, addr1));
    r_assert_cmpbufmem (buf2, 0, 256, ==, txbuf[0], 256);
    r_assert_cmpbufmem (buf2, 256, -1, ==, txbuf[1], 512);

    r_buffer_unref (buf1);
    r_buffer_unref (buf2);
  }

  r_assert_cmpint (r_socket_close (sock1), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_close (sock2), ==, R_SOCKET_OK);
  r_socket_unref (sock1);
  r_socket_unref (sock2);
  r_socket_address_unref (addr1);
  r_socket_address_unref (addr2);
  r_socket_address_unref (srcaddr);
}
RTEST_END;

