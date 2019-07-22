#CROSS = arm-linux-gnueabihf-

MAKE = make

CC = $(CROSS)gcc
LD = $(CROSS)ld
STRIP = $(CROSS)strip

ROOT_DIR = $(CURDIR)
MBEDTLS = ../mbedtls

CFLAGS = -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -O2
LDFLAGS =

INCLUDES = -I$(MBEDTLS)/include
LIBS = $(MBEDTLS)/library/libmbedx509.a $(MBEDTLS)/library/libmbedtls.a $(MBEDTLS)/library/libmbedcrypto.a

SOURCES = https_client.c ca_cert.c

OBJS = $(SOURCES:.c=.o)

.SUFFIXES:.c .o

all: https_client

mbedtls_make:
	@for dir in $(MBEDTLS); do \
		$(MAKE) -C $$dir ; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done

https_client: mbedtls_make $(OBJS)
	@echo Linking: $@ ....
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)
#	$(STRIP) -s $@

.c.o:
	@echo Compiling: $< ....
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<

clean:
	rm -f https_client *.o

mbedtls_clean:
	@for dir in $(MBEDTLS); do \
		$(MAKE) -C $$dir clean; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done1
