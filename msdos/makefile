#
#  Makefile for dos-libpcap. NB. This makefile requires a Borland
#  compatible make tool.
#
#  Targets:
#    Borland C 4.0+      (DOS large model)
#    Metaware HighC 3.3+ (PharLap 386|DosX)
#

.AUTODEPEND
.SWAP

!if "$(WATT_ROOT)" == ""
!error Environment variable "WATT_ROOT" not set.
!endif

WATT_INC = $(WATT_ROOT)\inc

DEFS   = -DMSDOS -DDEBUG -DNDIS_DEBUG -D_U_= -Dinline= \
         -DHAVE_STRERROR -DHAVE_LIMITS_H

ASM    = tasm.exe -t -l -mx -m2 -DDEBUG

SOURCE = grammar.cpp  scanner.cpp bpf_filt.cpp bpf_imag.cpp bpf_dump.cpp \
         etherent.cpp gencode.cpp nametoad.cpp pcap-dos.cpp optimize.cpp \
         savefile.cpp pcap.cpp msdos\ndis2.cpp msdos\pktdrvr.cpp \
         missing\snprintf.cpp

BORLAND_OBJ = $(SOURCE:.cpp=.obj) msdos\pkt_rx0.obj msdos\ndis_0.obj

HIGHC_OBJ   = $(SOURCE:.cpp=.o32) msdos\pkt_rx0.o32

all:
            @echo Usage: make pcap_bc.lib or pcap_hc.lib


pcap_bc.lib: bcc.arg $(BORLAND_OBJ) pcap_bc


pcap_hc.lib: hc386.arg $(HIGHC_OBJ)
            386lib $< @&&|
               -nowarn -nobackup -twocase -replace $(HIGHC_OBJ)
|

pcap_bc:    $(BORLAND_OBJ)
            @tlib pcap_bc.lib /C @&&|
               -+$(**:.obj=-+)
|

.cpp.obj:
            bcc.exe @bcc.arg -o$*.obj $*.cpp

.cpp.o32:
            hc386.exe @hc386.arg -o $*.o32 $*.cpp

.asm.obj:
            $(ASM) $*.asm, $*.obj

.asm.o32:
            $(ASM) -DDOSX=1 $*.asm, $*.o32

scanner.cpp: scanner.l
            flex -Ppcap_ -7 -oscanner.cpp scanner.l

grammar.cpp tokdefs.h: grammar.y
            bison --name-prefix=pcap_ --yacc --defines grammar.y
            - @del grammar.cpp
            - @del tokdefs.h
            ren y_tab.cpp grammar.cpp
            ren y_tab.h tokdefs.h

bcc.arg:    msdos\Makefile
            @copy &&|
              $(DEFS) -ml -c -v -3 -O2 -po -RT- -w-
              -I$(WATT_INC) -I. -I.\msdos\pm_drvr -H=$(TEMP)\bcc.sym
| $<

hc386.arg:  msdos\Makefile
            @copy &&|
            # -DUSE_32BIT_DRIVERS
              $(DEFS) -DDOSX=1 -w3 -c -g -O5
              -I$(WATT_INC) -I. -I.\msdos\pm_drvr
              -Hsuffix=.o32
              -Hnocopyr
              -Hpragma=Offwarn(491,553,572)
              -Hon=Recognize_library  # make memcpy/strlen etc. inline
              -Hoff=Behaved           # turn off some optimiser warnings
| $<

clean:
            @del *.obj
            @del *.o32
            @del *.lst
            @del *.map
            @del bcc.arg
            @del hc386.arg
            @del grammar.cpp
            @del tokdefs.h
            @del scanner.cpp
            @echo Cleaned

#
# dependencies
#
pkt_rx0.obj:  msdos\pkt_rx0.asm

bpf_filt.obj: bpf_filt.cpp pcap-int.h pcap.h pcap-bpf.h gnuc.h

bpf_imag.obj: bpf_imag.cpp pcap-int.h pcap.h pcap-bpf.h

bpf_dump.obj: bpf_dump.cpp pcap.h pcap-bpf.h

etherent.obj: etherent.cpp pcap-int.h pcap.h pcap-bpf.h pcap-namedb.h

optimize.obj: optimize.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h

savefile.obj: savefile.cpp pcap-int.h pcap.h pcap-bpf.h

pcap.obj: pcap.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h

grammar.obj: grammar.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pf.h pcap-namedb.h

scanner.obj: scanner.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pcap-namedb.h tokdefs.h

gencode.obj: gencode.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h \
  ethertype.h nlpid.h llc.h gencode.h atmuni31.h sunatmpos.h ppp.h sll.h \
  arcnet.h pf.h pcap-namedb.h

nametoad.obj: nametoad.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pcap-namedb.h ethertype.h

pcap-dos.obj: pcap-dos.cpp pcap.h pcap-bpf.h pcap-dos.h pcap-int.h \
  msdos\pktdrvr.h

pktdrvr.obj: msdos\pktdrvr.cpp gnuc.h pcap-dos.h pcap-int.h \
  pcap.h pcap-bpf.h msdos\pktdrvr.h msdos\pkt_stub.inc

ndis2.obj: msdos\ndis2.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h \
  msdos\ndis2.h

pkt_rx0.o32:  msdos\pkt_rx0.asm

bpf_filt.o32: bpf_filt.cpp pcap-int.h pcap.h pcap-bpf.h gnuc.h

bpf_imag.o32: bpf_imag.cpp pcap-int.h pcap.h pcap-bpf.h

bpf_dump.o32: bpf_dump.cpp pcap.h pcap-bpf.h

etherent.o32: etherent.cpp pcap-int.h pcap.h pcap-bpf.h pcap-namedb.h

optimize.o32: optimize.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h

savefile.o32: savefile.cpp pcap-int.h pcap.h pcap-bpf.h

pcap.o32: pcap.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h

grammar.o32: grammar.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pf.h pcap-namedb.h

scanner.o32: scanner.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pcap-namedb.h tokdefs.h

gencode.o32: gencode.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h \
  ethertype.h nlpid.h llc.h gencode.h atmuni31.h sunatmpos.h ppp.h sll.h \
  arcnet.h pf.h pcap-namedb.h

nametoad.o32: nametoad.cpp pcap-int.h pcap.h pcap-bpf.h gencode.h \
  pcap-namedb.h ethertype.h

pcap-dos.o32: pcap-dos.cpp pcap.h pcap-bpf.h pcap-dos.h pcap-int.h \
  msdos\pktdrvr.h

pktdrvr.o32: msdos\pktdrvr.cpp gnuc.h pcap-dos.h pcap-int.h \
  pcap.h pcap-bpf.h msdos\pktdrvr.h msdos\pkt_stub.inc

ndis2.o32: msdos\ndis2.cpp pcap-dos.h pcap-int.h pcap.h pcap-bpf.h \
  msdos\ndis2.h

