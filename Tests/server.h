#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <fstream>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <ctime>
#include <algorithm>
#include <cstring>
#include <cctype>
/**
 * Класс для управления системой логирования (шаблон Singleton)
 * Обеспечивает запись логов в файл и консоль с временными метками
 */
class Logger {
public:
    static Logger& getInstance();
    bool openLogFile(const std::string& filename);
    void logError(const std::string& msg, bool critical);
    void logMessage(const std::string& msg);
    void closeLogFile();

private:
    Logger() = default;
    std::ofstream logfile_;
};

/**
 * Класс для управления базой пользователей
 * Загружает пользователей из файла, проверяет существование, хранит пароли
 */
class UserManager {
public:
    bool loadUsers(const std::string& filename);
    bool userExists(const std::string& username) const;
    std::string getUserPassword(const std::string& username) const;
    void addUser(const std::string& username, const std::string& password);

private:
    std::unordered_map<std::string, std::string> users_;
};

/**
 * Утилитарный класс для криптографических операций
 * Содержит статические методы для работы с солями, хешами и строками
 */
class CryptoUtils {
public:
    static std::string generateSalt();
    static std::string sha224(const std::string& str);
    static std::string toUpper(const std::string& str);
    static std::string trim(const std::string& str);
};

/**
 * Класс для математических вычислений
 * Содержит алгоритмы обработки числовых данных
 */
class Calculator {
public:
    static uint64_t calculateAverage(const std::vector<uint64_t>& vec);
};

/**
 * Класс для низкоуровневых сетевых операций
 * Обеспечивает гарантированную отправку и прием данных через сокеты
 */
class NetworkUtils {
public:
    static bool recvAll(int sock, void* buf, size_t len);
    static bool sendAll(int sock, const void* buf, size_t len);
};

/**
 * Класс для обработки индивидуального клиентского соединения
 * Управляет всей логикой взаимодействия с одним клиентом
 */
class ClientHandler {
public:
    ClientHandler(int client_sock, std::shared_ptr<UserManager> user_manager);
    void handle();

private:
    bool authenticate();
    bool processData();
    bool receiveLogin(std::string& login);
    bool sendSalt(const std::string& salt);
    bool receiveHash(std::string& hash);
    bool verifyHash(const std::string& salt, const std::string& client_hash, 
                   const std::string& password);
    
    int client_sock_;
    std::shared_ptr<UserManager> user_manager_;
    std::string current_user_;
};

/**
 * Главный класс сервера
 * Управляет инициализацией, настройкой и основным циклом работы сервера
 */
class Server {
public:
    Server();
    ~Server();
    
    bool initialize(int argc, char* argv[]);
    void run();
    void stop();

private:
    bool parseArguments(int argc, char* argv[]);
    bool createSocket();
    bool setupAddress();
    bool startListening();
    void cleanup();
    
    int server_sock_;
    int port_;
    std::string users_db_file_;
    std::string log_file_;
    std::shared_ptr<UserManager> user_manager_;
    bool running_;
};
