# Project: Secure Socket Exchange Debug

CPP       = g++ -D__DEBUG__
CC        = gcc -D__DEBUG__
OBJDIR    = ../obj/Debug/
OUTPUTDIR = ../../Debug/
OBJ       = $(OBJDIR)RSAKeyManager.o $(OBJDIR)byteconvert.o $(OBJDIR)Socket.o $(OBJDIR)PackageManager.o
LINKOBJ   = $(OBJDIR)RSAKeyManager.o $(OBJDIR)byteconvert.o $(OBJDIR)Socket.o $(OBJDIR)PackageManager.o \
           -lcryptopp -lWs2_32 -lMswsock -lAdvapi32
LIBS      = -L"crypto++"
INCS      = -I"crypto++"
CXXINCS   = -I"crypto++"
CXXFLAGS  = $(INCS)    -std=c++11 -Wall -pedantic -g3
CFLAGS    = $(CXXINCS) -std=c11   -Wall -pedantic -g3
BIN       = SocSecExc.dll
DEF       = SocSecExc.def
STATIC    = SocSecExc.lib

.PHONY: all all-before all-after clean clean-custom

all: all-before $(OUTPUTDIR)$(BIN) all-after

clean:
	rm -rf $(OBJ) $(OUTPUTDIR)$(BIN) $(OUTPUTDIR)$(DEF) $(OUTPUTDIR)$(STATIC)

#Object-file dependencies

$(OBJDIR)Socket.o: Socket.cpp Socket.h
	$(CPP) -c $< -o $@ $(CXXFLAGS)

$(OBJDIR)byteconvert.o: byteconvert.c byteconvert.h
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJDIR)PackageManager.o: PackageManager.cpp PackageManager.h
	$(CPP) -c $< -o $@ $(CXXFLAGS)

$(OBJDIR)RSAKeyManager.o: RSAKeyManager.cpp RSAKeyManager.h
	$(CPP) -c $< -o $@ $(CXXFLAGS)
	
$(OUTPUTDIR)$(BIN): $(OBJ)
	$(CPP) -shared $(LINKOBJ) $(LIBS) -o $@ -Wl,--output-def,$(OUTPUTDIR)$(DEF),--out-implib,$(OUTPUTDIR)$(STATIC)
