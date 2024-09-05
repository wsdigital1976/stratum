
CC= gcc -no-pie

CFLAGS= -g -march=native
SQLFLAGS= `mysql_config --cflags --libs`

#CFLAGS=-c -O2 -I /usr/include/mysql
#LDFLAGS=-O2 `mysql_config --libs`

LDLIBS=iniparser/libiniparser.a algos/libalgos.a sha3/libhash.a -Isecp256k1/include secp256k1/.libs/libsecp256k1.a -lpthread -lgmp -lm -lstdc++ -lssl -lcrypto -lsodium
LDLIBS+=-lmysqlclient -lcurl

SOURCES=stratum.cpp db.cpp coind.cpp coind_aux.cpp coind_template.cpp coind_submit.cpp util.cpp list.cpp \
	rpc.cpp job.cpp job_send.cpp job_core.cpp merkle.cpp share.cpp socket.cpp coinbase.cpp \
	client.cpp client_submit.cpp client_core.cpp client_difficulty.cpp remote.cpp remote_template.cpp \
	user.cpp object.cpp json.cpp base58.cpp humanize_number.cpp

CFLAGS += -DHAVE_CURL
SOURCES += rpc_curl.cpp
#LDCURL = $(shell /usr/bin/pkg-config --static --libs libcurl)
#LDFLAGS += $(LDCURL)

OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=stratum

CODEDIR1=algos
CODEDIR2=sha3
CODEDIR3=iniparser
CODEDIR4=secp256k1


.PHONY: projectcode1 projectcode2 projectcode3 projectcode4

all: gitsubmodules projectcode1 projectcode2 projectcode3 projectcode4 $(SOURCES) $(OUTPUT)
buildonly: projectcode1 projectcode2 projectcode3 projectcode4 $(SOURCES) $(OUTPUT)

gitsubmodules:
	git submodule init && git submodule update
projectcode1:
	$(MAKE) -C $(CODEDIR1)

projectcode2:
	$(MAKE) -C $(CODEDIR2)
	
projectcode3:
	$(MAKE) -C $(CODEDIR3)

projectcode4:
ifeq ($(wildcard $(CODEDIR4)/.libs/libsecp256k1.a), )
	cd $(CODEDIR4) && chmod +x autogen.sh && ./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --with-bignum=no --enable-endomorphism && $(MAKE)
endif

$(SOURCES): stratum.h util.h

$(OUTPUT): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDLIBS) $(LDFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $(SQLFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f stratum
	rm -f *.o
	rm -f algos/*.o
	rm -f algos/*.a
	rm -f iniparser/*.o
	rm -f iniparser/src/*.o
	rm -f iniparser/*.a
	rm -f sha3/*.o
	rm -f sha3/*.a
	rm -f algos/ar2/*.o
	rm -f algos/blake2/*.o
	rm -f algos/blake2-ref/*.o
	rm -f algos/cryptonote/*.o
	rm -f algos/cryptonote/crypto/*.o
	rm -f algos/heavyhash/*.o
	rm -f algos/honeycomb/*.o
	rm -f algos/SWIFFTX/*.o
	rm -f algos/yespower/*.o
	rm -f algos/yespower/crypto/*.o
	
install: clean all
	strip -s stratum
	cp stratum /usr/local/bin/
	cp stratum ../bin/

