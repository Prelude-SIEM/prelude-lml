# Copyright (C) 2002-2010 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the specification of how gnulib-tool is used.
# It acts as a cache: It is written and read by gnulib-tool.
# In projects using CVS, this file is meant to be stored in CVS,
# like the configure.ac and various Makefile.am files.


# Specification in the form of a command-line invocation:
#   gnulib-tool --import --dir=. --lib=libmissing --source-base=libmissing --m4-base=libmissing/m4 --doc-base=libmissing/doc --tests-base=libmissing/tests --aux-dir=. --with-tests --lgpl --libtool --macro-prefix=gl --no-vc-files bind close fnmatch-gnu getaddrinfo glob iconv imaxabs inet_ntop ioctl mktime nl_langinfo pathmax recvfrom servent sigaction sleep snprintf snprintf-posix socket socklen strptime strsep sys_select

# Specification in the form of a few gnulib-tool.m4 macro invocations:
gl_LOCAL_DIR([])
gl_MODULES([
  bind
  close
  fnmatch-gnu
  getaddrinfo
  glob
  iconv
  imaxabs
  inet_ntop
  ioctl
  mktime
  nl_langinfo
  pathmax
  recvfrom
  servent
  sigaction
  sleep
  snprintf
  snprintf-posix
  socket
  socklen
  strptime
  strsep
  sys_select
])
gl_AVOID([])
gl_SOURCE_BASE([libmissing])
gl_M4_BASE([libmissing/m4])
gl_PO_BASE([])
gl_DOC_BASE([libmissing/doc])
gl_TESTS_BASE([libmissing/tests])
gl_WITH_TESTS
gl_LIB([libmissing])
gl_LGPL
gl_MAKEFILE_NAME([])
gl_LIBTOOL
gl_MACRO_PREFIX([gl])
gl_PO_DOMAIN([])
gl_VC_FILES([false])
