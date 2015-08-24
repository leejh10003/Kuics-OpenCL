CC = g++
LIBB = -L/usr/local/cuda/lib64 -L/usr/local/cuda/lib32 -L/usr/local/cuda/lib
INC_DIR = -I/usr/local/cuda/include
ifeq ($(OS),Windows_NT)
	CCFLAGS += -D WIN32
    ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
		CCFLAGS += -D AMD64
	endif
	ifeq ($(PROCESSOR_ARCHITECTURE),x86)
		CCFLAGS += -D IA32
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCFLAGS += -D LINUX -lOpenCL
	endif
	ifeq ($(UNAME_S),Darwin)
		CCFLAGS += -D OSX -framework OpenCL
	endif
	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		CCFLAGS += -D AMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		CCFLAGS += -D IA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		CCFLAGS += -D ARM
	endif
endif
testg++: BasicIO.c ErrorHandle.c Hash.c jjOpenCLBasic.cc jjOpenCLPlatformInitialize.cpp main.cc NPKICrack.c Seed.c
	$(CC) BasicIO.c ErrorHandle.c Hash.c jjOpenCLBasic.cc jjOpenCLPlatformInitialize.cpp main.cc NPKICrack.c Seed.c -o testg++ $(CCFLAGS) $(LIBB) $(INC_DIR)