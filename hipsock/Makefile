obj-m += hipsock.o
hipsock-objs := debug.o builder.o misc.o af_hip.o


# Default assumption of the linux sources. Do not change! Use the
# command line option.
#
LINUX=/usr/src/linux
LIBHIPTOOL=../libhiptool
LIBHIPCORE=../libhipcore
HIPD=../hipd
LN=ln -sf

all:	warn links
	CFLAGS=-I../hipd make -C $(LINUX) M=$(PWD) modules

links:
	$(LN) $(LIBHIPCORE)/builder.c
	$(LN) $(LIBHIPCORE)/builder.h
	$(LN) $(LIBHIPCORE)/protodefs.h
	$(LN) $(LIBHIPCORE)/utils.h
	$(LN) $(LIBHIPCORE)/misc.c
	$(LN) $(LIBHIPCORE)/misc.h
	$(LN) $(LIBHIPCORE)/state.h
	$(LN) $(LIBHIPCORE)/icomm.h
	$(LN) $(LIBHIPCORE)/ife.h
	$(LN) $(HIPD)/hidb.h
	$(LN) $(HIPD)/registration.h
#	$(LN) $(HIPD)/timer.h

warn:
	@echo ""
	@echo "##########################################################"
	@echo "# Default assumption of kernel sources in /usr/src/linux #"
	@echo "# Override with make LINUX=/path/to/linux/sources        #"
	@echo "##########################################################"
	@echo ""

clean:
	make -C $(LINUX) M=$(PWD) clean
