CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lssl -lcrypto -lUnitTest++
TARGET = tests
SOURCES = server.cpp tests.cpp

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean
