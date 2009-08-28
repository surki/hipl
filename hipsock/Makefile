obj-m += hipsock.o
hipsock-objs := debug.o builder.o misc.o af_hip.o


# Default assumption of the linux sources. Do not change! Use the
# command line option.
#
LINUX=/usr/src/linux
LIBHIPTOOL=../libhiptool
LIBINET6=../libinet6
HIPD=../hipd
LN=ln -sf

all:	warn links
	CFLAGS=-I../hipd make -C $(LINUX) M=$(PWD) modules

links:
	$(LN) $(LIBINET6)/builder.c
	$(LN) $(LIBINET6)/builder.h
	$(LN) $(LIBINET6)/protodefs.h
	$(LN) $(LIBINET6)/utils.h
	$(LN) $(LIBINET6)/misc.c
	$(LN) $(LIBINET6)/misc.h
	$(LN) $(LIBINET6)/state.h
	$(LN) $(LIBINET6)/icomm.h
	$(LN) $(LIBINET6)/ife.h
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
