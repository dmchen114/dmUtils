noinst_PROGRAMS=test
test_SOURCES=main.c timer_test.c
test_LDADD=$(top_srcdir)/src/dmUtils/libdmutils.a 
test_LDFLAGS=-D_GNU_SOURCE
DEFS+=-D_GNU_SOURCE
LIBS=-lpthread -lrt -lm -ldl
