CXX = g++
CXXFLAGS = -std=c++20 -Wall

all: server client

server: server.cpp
	    $(CXX) $(CXXFLAGS) -o server server.cpp p1_helper.cpp -lssl -lcrypto

clean:
	    rm -f server
