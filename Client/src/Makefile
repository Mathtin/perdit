# Project: Perdit Client Debug

CPP       = g++ -D__DEBUG__
CC        = gcc -D__DEBUG__
OBJDIR    = ../obj/Debug/
RESDIR    = ../res/
OUTPUTDIR = ../../Debug/
SSESRCDIR = ../../SocSecExc/src/
OBJ       = $(OBJDIR)main.o $(OBJDIR)PerditClient.o $(RESDIR)PerditClient.res
LINKOBJ   = $(OBJDIR)main.o $(OBJDIR)PerditClient.o $(RESDIR)PerditClient.res -lSocSecExc -lcryptopp
LIBS      = -L"$(OUTPUTDIR)" -L"$(SSESRCDIR)crypto++"
INCS      = -I"$(SSESRCDIR)" -I"$(SSESRCDIR)crypto++"
CXXINCS   = -I"$(SSESRCDIR)" -I"$(SSESRCDIR)crypto++"
CXXFLAGS  = $(INCS)    -std=c++11 -Wall -pedantic -g3
CFLAGS    = $(CXXINCS) -std=c11   -Wall -pedantic -g3
BIN       = PerditClient.exe

.PHONY: all all-before all-after clean clean-custom

all: all-before $(OUTPUTDIR)$(BIN) all-after

clean:
	rm -rf $(OBJ) $(OUTPUTDIR)$(BIN)

#Object-file dependencies

$(RESDIR)PerditClient.res: PerditClient.rc
	windres $< -O coff -o $@

$(OBJDIR)PerditClient.o: PerditClient.cpp  PerditClient.h $(SSESRCDIR)Socket.h $(SSESRCDIR)RSAKeyManager.h $(SSESRCDIR)PackageManager.h
	$(CPP) -c $< -o $@ $(CXXFLAGS)

$(OBJDIR)main.o: main.cpp
	$(CPP) -c $< -o $@ $(CXXFLAGS)

$(OUTPUTDIR)$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(OUTPUTDIR)$(BIN) $(LIBS)