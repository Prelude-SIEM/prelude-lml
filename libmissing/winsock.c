/* winsock.c --- wrappers for Windows socket functions

   Copyright (C) 2008 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Paolo Bonzini */

#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/socket.h>
#if GNULIB_IOCTL
#include <sys/ioctl.h>
#endif

#undef socket
#undef connect
#undef accept
#undef bind
#undef getpeername
#undef getsockname
#undef getsockopt
#undef listen
#undef recv
#undef send
#undef recvfrom
#undef sendto
#undef setsockopt
#undef shutdown

#define FD_TO_SOCKET(fd)   ((SOCKET) _get_osfhandle ((fd)))
#define SOCKET_TO_FD(fh)   (_open_osfhandle ((long) (fh), O_RDWR | O_BINARY))


static inline void
set_winsock_errno (void)
{
  int err = WSAGetLastError ();
  WSASetLastError (0);

  /* Map some WSAE* errors to the runtime library's error codes.  */
  switch (err)
    {
    case WSA_INVALID_HANDLE:
      errno = EBADF;
      break;
    case WSA_NOT_ENOUGH_MEMORY:
      errno = ENOMEM;
      break;
    case WSA_INVALID_PARAMETER:
      errno = EINVAL;
      break;
    case WSAEWOULDBLOCK:
      errno = EWOULDBLOCK;
      break;
    case WSAENAMETOOLONG:
      errno = ENAMETOOLONG;
      break;
    case WSAENOTEMPTY:
      errno = ENOTEMPTY;
      break;
    default:
      errno = (err > 10000 && err < 10025) ? err - 10000 : err;
      break;
    }
}


/* Hook for gnulib module close.  */

#if HAVE__GL_CLOSE_FD_MAYBE_SOCKET
int
_gl_close_fd_maybe_socket (int fd)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  WSANETWORKEVENTS ev;

  ev.lNetworkEvents = 0xDEADBEEF;
  WSAEnumNetworkEvents (sock, NULL, &ev);
  if (ev.lNetworkEvents != 0xDEADBEEF)
    {
      /* FIXME: other applications, like squid, use an undocumented
	 _free_osfhnd free function.  But this is not enough: The 'osfile'
	 flags for fd also needs to be cleared, but it is hard to access it.
	 Instead, here we just close twice the file descriptor.  */
      if (closesocket (sock))
	{
	  set_winsock_errno ();
	  return -1;
	}
      else
	{
	  /* This call frees the file descriptor and does a
	     CloseHandle ((HANDLE) _get_osfhandle (fd)), which fails.  */
	  _close (fd);
	  return 0;
	}
    }
  else
    return _close (fd);
}
#endif


/* Wrappers for WinSock functions.  */

#if GNULIB_SOCKET
int
rpl_socket (int domain, int type, int protocol)
{
  /* We have to use WSASocket() to create non-overlapped IO sockets.
     Overlapped IO sockets cannot be used with read/write.  */
  SOCKET fh = WSASocket (domain, type, protocol, NULL, 0, 0);

  if (fh == INVALID_SOCKET)
    {
      set_winsock_errno ();
      return -1;
    }
  else
    return SOCKET_TO_FD (fh);
}
#endif

#if GNULIB_CONNECT
int
rpl_connect (int fd, struct sockaddr *sockaddr, int len)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = connect (sock, sockaddr, len);
  if (r < 0)
    {
      /* EINPROGRESS is not returned by WinSock 2.0; for backwards
	 compatibility, connect(2) uses EWOULDBLOCK.  */
      if (WSAGetLastError () == WSAEWOULDBLOCK)
        WSASetLastError (WSAEINPROGRESS);

      set_winsock_errno ();
    }

  return r;
}
#endif

#if GNULIB_ACCEPT
int
rpl_accept (int fd, struct sockaddr *addr, int *addrlen)
{
  SOCKET fh = accept (FD_TO_SOCKET (fd), addr, addrlen);
  if (fh == INVALID_SOCKET)
    {
      set_winsock_errno ();
      return -1;
    }
  else
    return SOCKET_TO_FD (fh);
}
#endif

#if GNULIB_BIND
int
rpl_bind (int fd, struct sockaddr *sockaddr, int len)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = bind (sock, sockaddr, len);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_GETPEERNAME
int
rpl_getpeername (int fd, struct sockaddr *addr, int *addrlen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = getpeername (sock, addr, addrlen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_GETSOCKNAME
int
rpl_getsockname (int fd, struct sockaddr *addr, int *addrlen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = getsockname (sock, addr, addrlen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_GETSOCKOPT
int
rpl_getsockopt (int fd, int level, int optname, void *optval, int *optlen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = getsockopt (sock, level, optname, optval, optlen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_LISTEN
int
rpl_listen (int fd, int backlog)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = listen (sock, backlog);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_IOCTL
int
rpl_ioctl (int fd, int req, ...)
{
  void *buf;
  va_list args;
  SOCKET sock;
  int r;

  va_start (args, req);
  buf = va_arg (args, void *);
  va_end (args);

  sock = FD_TO_SOCKET (fd);
  r = ioctlsocket (sock, req, buf);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_RECV
int
rpl_recv (int fd, void *buf, int len, int flags)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = recv (sock, buf, len, flags);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_SEND
int
rpl_send (int fd, const void *buf, int len, int flags)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = send (sock, buf, len, flags);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_RECVFROM
int
rpl_recvfrom (int fd, void *buf, int len, int flags, struct sockaddr *from,
	      int *fromlen)
{
  int frombufsize = *fromlen;
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = recvfrom (sock, buf, len, flags, from, fromlen);

  if (r < 0)
    set_winsock_errno ();

  /* Winsock recvfrom() only returns a valid 'from' when the socket is
     connectionless.  POSIX gives a valid 'from' for all types of sockets.  */
  else if (*fromlen == frombufsize)
    rpl_getpeername (fd, from, fromlen);

  return r;
}
#endif

#if GNULIB_SENDTO
int
rpl_sendto (int fd, const void *buf, int len, int flags,
	    struct sockaddr *to, int tolen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = sendto (sock, buf, len, flags, to, tolen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_SETSOCKOPT
int
rpl_setsockopt (int fd, int level, int optname, const void *optval, int optlen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = setsockopt (sock, level, optname, optval, optlen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif

#if GNULIB_SHUTDOWN
int
rpl_shutdown (int fd, int how)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = shutdown (sock, how);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
#endif
