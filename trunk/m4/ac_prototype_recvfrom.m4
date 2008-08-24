dnl @synopsis AC_PROTOTYPE_ACCEPT
dnl
dnl Requires the AC_PROTOTYPE macro.
dnl
dnl Find the type of argument two and three of accept. User
dnl must include the following in acconfig.h:
dnl
dnl /* Type of second argument of accept */
dnl #undef ACCEPT_ARG2
dnl
dnl /* Type of third argument of accept */
dnl #undef ACCEPT_ARG3
dnl
dnl @version $Id: ac_prototype_accept.m4,v 1.1.1.1 2001/07/26 00:46:29 guidod Exp $
dnl @author Loic Dachary <loic@senga.org>
dnl
AC_DEFUN([AC_PROTOTYPE_RECVFROM],[
AC_PROTOTYPE(recvfrom,
 [
  #include <sys/types.h>
  #include <sys/socket.h>
 ],
 [
  int a = 0;
  void * b = 0;
  size_t c = 0;
  int d = 0;
  ARG5 * e = 0;
  ARG6 * f = 0;
  recvfrom(a, b, c, d, e, f);
 ],
 ARG5, [struct sockaddr, void],
 ARG6, [socklen_t, size_t, int, unsigned int, long unsigned int])
])
