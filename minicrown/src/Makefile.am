AUTOMAKE_OPTIONS=foreign
DISTCLEANFILES=*~
AM_CPPFLAGS=-I$(builddir)

EXTRA_DIST=\
src/misc.h \
src/gcm.h \
src/kybtestlib.h

bin_PROGRAMS=\
minicrown_encrypt \
minicrown_decrypt \
minicrown_keygen

TESTS=\
gcm_test
check_PROGRAMS=$(TESTS)

gcm_test_SOURCES=\
src/main.cc \
src/gcm.cc \
src/gcm_test.cc \
src/kybtestlib.cc

minicrown_encrypt_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/gcm.cc \
src/encrypt.cc

minicrown_decrypt_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/gcm.cc \
src/decrypt.cc

minicrown_keygen_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/gcm.cc \
src/keygen.cc

