AC_INIT([SMBNetFS],[0.6.0])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_CC

AC_CHECK_FUNCS([setxattr])
AC_CHECK_FUNC(backtrace_symbols_fd,
    [AC_DEFINE([HAVE_BACKTRACE], [], [Linux])]
)
AC_CHECK_FUNC(strndup,
    [AC_DEFINE([HAVE_STRNDUP], [], [Linux])]
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

dnl **********************
dnl *** Tests for glib-2.0 ***
dnl **********************
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.30])
LIBS="$LIBS $GLIB_LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"

dnl *******************************
dnl *** Tests for gnome-keyring ***
dnl *******************************
AC_ARG_WITH(gnome-keyring,
	[AS_HELP_STRING(--with-gnome-keyring=@<:@no/yes@:>@,
		use gnome-keyring as password storage @<:@default=auto@:>@)],
	,
	[with_gnome_keyring=maybe])

if test x"$with_gnome_keyring" != xno; then
	PKG_CHECK_MODULES(GNOME_KEYRING, [gnome-keyring-1 >= 2.28],
		[AC_DEFINE([HAVE_GNOME_KEYRING], [],
			[use gnome-keyring as password storage])],
		[# mandatory depend
		if test x"$with_gnome_keyring" = xyes; then
			AC_MSG_ERROR([unable to find usable gnome-keyring])
		fi])
	LIBS="$LIBS $GNOME_KEYRING_LIBS"
	CFLAGS="$CFLAGS $GNOME_KEYRING_CFLAGS"
fi

dnl ******************************
dnl *** Tests for libsmbclient ***
dnl ******************************
PKG_CHECK_MODULES(SMBCLIENT, smbclient, [libsmbclient_found=yes], [libsmbclient_found=no])
if test x"$libsmbclient_found" = xyes; then
	AC_DEFINE(HAVE_LIBSMBCLIENT_3_2, 1, [Using Samba-3.2 api])

	LIBS="$LIBS $SMBCLIENT_LIBS"
	CFLAGS="$CFLAGS $SMBCLIENT_CFLAGS"
else
	#LIBS="/tmp/s/test/libsmbclient.a $FUSE_LIBS -lc -lcrypt -lresolv -lnsl -ldl"

	AC_CHECK_LIB(smbclient, smbc_new_context, [], [
		echo "Error!!! libsmbclient >= 3.0.20 required."
		exit 1
	])

	AC_CHECK_LIB(smbclient, smbc_setOptionUserData,
	    [AC_DEFINE(HAVE_LIBSMBCLIENT_3_2, 1, [Using Samba-3.2 api])],
	    [AC_CHECK_MEMBER(SMBCCTX.close_fn, [],
		[echo "Error!!! libsmbclient >= 3.0.20 required."; exit 1],
		[#include <libsmbclient.h>]
	    )]
	)

	echo ""
	echo "  Do not use old libsmbclient version, libsmbclient >= 3.2.0 is recommended."
	echo ""
fi

dnl ******************
dnl *** Final step ***
dnl ******************

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
