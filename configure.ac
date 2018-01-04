AC_INIT([SMBNetFS],[0.6.1])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_CC

AC_CHECK_FUNC(backtrace_symbols_fd,
    [AC_DEFINE([HAVE_BACKTRACE], [], [Linux])]
)
AC_CHECK_FUNC(setlocale, [found_setlocale=yes])
if test "x$found_setlocale" != "xyes" ; then
    AC_MSG_ERROR([*** No setlocale() implementation found in C library])
fi


export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
CFLAGS="$CFLAGS -Wall -W"
LDFLAGS="$LDFLAGS -rdynamic"


dnl ***********************
dnl *** Tests for iconv ***
dnl ***********************
AC_ARG_WITH(libiconv,
    [AS_HELP_STRING(--with-libiconv=@<:@no/gnu/native@:>@,
	use the libiconv library)],
    ,
    [with_libiconv=maybe])

found_iconv=no
case $with_libiconv in
    maybe)
	# Check in the C library first
	AC_CHECK_FUNC(iconv_open, [with_libiconv=no; found_iconv=yes])

	# Check if we have GNU libiconv
	if test $found_iconv = "no"; then
	    AC_CHECK_LIB(iconv, libiconv_open, 
		[with_libiconv=gnu; found_iconv=yes])
	fi

	# Check if we have a iconv in -liconv, possibly from vendor
	if test $found_iconv = "no"; then
	    AC_CHECK_LIB(iconv, iconv_open, 
		[with_libiconv=native; found_iconv=yes])
	fi
	;;
    no)
	AC_CHECK_FUNC(iconv_open, [with_libiconv=no; found_iconv=yes])
        ;;
    gnu|yes)
	AC_CHECK_LIB(iconv, libiconv_open, 
	    [with_libiconv=gnu; found_iconv=yes])
	;;
    native)
	AC_CHECK_LIB(iconv, iconv_open, 
	    [with_libiconv=native; found_iconv=yes])
	;;
esac

if test "x$found_iconv" = "xno" ; then
    AC_MSG_ERROR([*** No iconv() implementation found in C library or libiconv])
fi

case $with_libiconv in
    gnu)
	AC_DEFINE(USE_LIBICONV_GNU, 1, [Using GNU libiconv])
	;;
    native)
	AC_DEFINE(USE_LIBICONV_NATIVE, 1, 
	    [Using a native implementation of iconv in a separate library])
	;;
esac


dnl **********************
dnl *** Tests for fuse ***
dnl **********************
PKG_CHECK_MODULES(FUSE, [fuse >= 2.6])
LIBS="$LIBS $FUSE_LIBS"
CFLAGS="$CFLAGS -D_REENTRANT -D_GNU_SOURCE -DFUSE_USE_VERSION=26 $FUSE_CFLAGS"

dnl **************************
dnl *** Tests for glib-2.0 ***
dnl **************************
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.30])
LIBS="$LIBS $GLIB_LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"

dnl ***************************
dnl *** Tests for libsecret ***
dnl ***************************
AC_ARG_WITH(libsecret,
	[AS_HELP_STRING(--with-libsecret=@<:@no/yes@:>@,
		use libsecret as password storage @<:@default=auto@:>@)],
	,
	[with_libsecret=maybe])

if test x"$with_libsecret" != xno; then
	PKG_CHECK_MODULES(LIBSECRET, [libsecret-1 >= 0.18.5],
		[AC_DEFINE([HAVE_LIBSECRET], [],
			[use libsecret as password storage])],
		[# mandatory depend
		if test x"$with_libsecret" = xyes; then
			AC_MSG_ERROR([unable to find usable libsecret])
		fi])
	LIBS="$LIBS $LIBSECRET_LIBS"
	CFLAGS="$CFLAGS $LIBSECRET_CFLAGS"
fi

dnl ******************************
dnl *** Tests for libsmbclient ***
dnl ******************************
PKG_CHECK_MODULES(SMBCLIENT, [smbclient])
AC_CHECK_LIB(smbclient, smbc_setOptionUseCCache, [], [
	echo "Error!!! libsmbclient >= 3.5 required."
	exit 1
])

LIBS="$LIBS $SMBCLIENT_LIBS"
CFLAGS="$CFLAGS $SMBCLIENT_CFLAGS"

dnl ******************
dnl *** Final step ***
dnl ******************

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
