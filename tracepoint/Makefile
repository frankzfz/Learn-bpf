CLANG = clang

EXECABLE = tracepoint 

BPFCODE = tracepoint_kernel 

BPFTOOLS = /data/kernel/v1/linux-stable/samples/bpf

CCINCLUDE += -I/data/kernel/v1/linux-stable/tools/testing/selftests/bpf

LOADINCLUDE += -I/data/kernel/v1/linux-stable/samples/bpf
LOADINCLUDE += -I/data/kernel/v1/linux-stable//tools/lib
LOADINCLUDE += -I/data/kernel/v1/linux-stable/tools/perf
LOADINCLUDE += -I/data/kernel/v1/linux-stable/tools/include
LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf

# Setting -DHAVE_ATTR_TEST=0 for the kernel containing below patch:
# 06f84d1989b7 perf tools: Make usage of test_attr__* optional for perf-sys.h
#
# The patch was included in Linus's tree starting v5.5-rc1, but was also included
# in stable kernel branch linux-5.4.y. So it's hard to determine whether a kernel
# is affected based on the kernel version alone:
# - for a v5.4 kernel from Linus's tree, no;
# - for a v5.4 kernel from the stable tree (used by many distros), yes.
#
# So let's look at the actual kernel source code to decide.
#
# See more context at:
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=06f84d1989b7e58d56fa2e448664585749d41221
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fce9501aec6bdda45ef3a5e365a5e0de7de7fe2d
CFLAGS += $(shell grep -q "define HAVE_ATTR_TEST 1" /data/kernel/v1/linux-stable/tools/perf/perf-sys.h \
                  && echo "-DHAVE_ATTR_TEST=0")

.PHONY: clean $(CLANG) tracepoint build

clean:
	rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c}
	$(CLANG) -O2 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o ${BPFCODE:=.o}

tracepoint: build
	clang $(CFLAGS) -o $(EXECABLE) -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
        tracepoint_user.c

$(EXECABLE): tracepoint 

.DEFAULT_GOAL := $(EXECABLE)
