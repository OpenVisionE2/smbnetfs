#!/bin/sh

aclocal
autoheader
automake --gnu --add-missing --copy --foreign
autoconf -f -Wall


