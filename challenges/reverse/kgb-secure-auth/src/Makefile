all: client server

client: client.cpp common.h words.h
	g++ -o client client.cpp
	strip client

server: server.cpp common.h words.h
	g++ -o server server.cpp
	strip server

words.h: words.txt
	xxd -i words.txt > words.h

clean:
	rm -f client server words.h
