CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lcrypto
OBJS = main.o server.o

all: server

server: $(OBJS)
	$(CXX) $(CXXFLAGS) -o server $(OBJS) $(LIBS)

main.o: main.cpp server.h
	$(CXX) $(CXXFLAGS) -c main.cpp

server.o: server.cpp server.h
	$(CXX) $(CXXFLAGS) -c server.cpp

clean:
	rm -f server $(OBJS)

.PHONY: all clean
