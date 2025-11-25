CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lssl -lcrypto

# Основная программа
OBJS = main.o server.o
SERVER_TARGET = server

# Тесты
TEST_SOURCES = server.cpp tests.cpp
TEST_TARGET = tests
TEST_LIBS = -lssl -lcrypto -lUnitTest++

# Правила по умолчанию
all: $(SERVER_TARGET)

# Сборка основной программы
$(SERVER_TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(SERVER_TARGET) $(OBJS) $(LIBS)

main.o: main.cpp server.h
	$(CXX) $(CXXFLAGS) -c main.cpp

server.o: server.cpp server.h
	$(CXX) $(CXXFLAGS) -c server.cpp

# Сборка и запуск тестов
test: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TEST_TARGET) $(TEST_SOURCES) $(TEST_LIBS)

run-test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Утилиты
clean:
	rm -f $(SERVER_TARGET) $(TEST_TARGET) $(OBJS)

.PHONY: all test run-test clean
