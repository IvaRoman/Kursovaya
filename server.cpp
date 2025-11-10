#include "server.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>
#include <algorithm>
#include <cstring>

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА LOGGER
// ============================================================================

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

/**
 * Открывает файл для записи логов
 */
bool Logger::openLogFile(const std::string& filename) {
    logfile_.open(filename, std::ios::app);
    return logfile_.is_open();
}

/**
 * Записывает сообщение об ошибке в лог с указанием критичности
 */
void Logger::logError(const std::string& msg, bool critical) {
    // БЛОК: ФОРМАТИРОВАНИЕ ВРЕМЕНИ
    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt)-1] = '\0';  // Убираем символ новой строки
    
    std::string log_msg = std::string(dt) + " " + (critical ? "CRITICAL: " : "ERROR: ") + msg;
    
    // БЛОК: ЗАПИСЬ В ФАЙЛ И КОНСОЛЬ
    if (logfile_.is_open()) {
        logfile_ << log_msg << std::endl;
    }
    std::cout << "LOG: " << msg << std::endl;
}

/**
 * Записывает информационное сообщение в лог
 */
void Logger::logMessage(const std::string& msg) {
    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt)-1] = '\0';
    
    if (logfile_.is_open()) {
        logfile_ << dt << " INFO: " << msg << std::endl;
    }
    std::cout << "INFO: " << msg << std::endl;
}

/**
 * Закрывает файл логов
 */
void Logger::closeLogFile() {
    if (logfile_.is_open()) {
        logfile_.close();
    }
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА USERMANAGER
// ============================================================================

/**
 * Загружает пользователей из файла в формате "логин:пароль"
 */
bool UserManager::loadUsers(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    // БЛОК: ЧТЕНИЕ И ПАРСИНГ ФАЙЛА
    while (std::getline(file, line)) {
        line = CryptoUtils::trim(line);
        if (line.empty()) continue;
        
        // БЛОК: РАЗБИЕНИЕ СТРОКИ НА ЛОГИН И ПАРОЛЬ
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string user = CryptoUtils::trim(line.substr(0, pos));
            std::string pass = CryptoUtils::trim(line.substr(pos + 1));
            users_[user] = pass;
            std::cout << "Loaded user: '" << user << "'" << std::endl;
        }
    }
    return true;
}

bool UserManager::userExists(const std::string& username) const {
    return users_.find(username) != users_.end();
}

std::string UserManager::getUserPassword(const std::string& username) const {
    auto it = users_.find(username);
    return (it != users_.end()) ? it->second : "";
}

void UserManager::addUser(const std::string& username, const std::string& password) {
    users_[username] = password;
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА CRYPTOUTILS
// ============================================================================

/**
 * Генерирует случайную соль для хеширования паролей
 */
std::string CryptoUtils::generateSalt() {
    // БЛОК: ГЕНЕРАЦИЯ СЛУЧАЙНОГО ЧИСЛА
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    uint64_t salt_val = dis(gen);
    
    // БЛОК: ПРЕОБРАЗОВАНИЕ В HEX-СТРОКУ
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << salt_val;
    return ss.str();
}

/**
 * Вычисляет SHA-224 хеш от входной строки
 */
std::string CryptoUtils::sha224(const std::string& str) {
    unsigned char hash[SHA224_DIGEST_LENGTH];
    // БЛОК: ВЫЧИСЛЕНИЕ ХЕША С ПОМОЩЬЮ OPENSSL
    SHA224(reinterpret_cast<const unsigned char*>(str.c_str()), str.size(), hash);

    // БЛОК: ПРЕОБРАЗОВАНИЕ БАЙТОВ В HEX-СТРОКУ
    std::stringstream ss;
    for (int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

/**
 * Преобразует строку в верхний регистр
 */
std::string CryptoUtils::toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

/**
 * Удаляет пробельные символы с начала и конца строки
 */
std::string CryptoUtils::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА CALCULATOR
// ============================================================================

/**
 * Вычисляет среднее арифметическое значений в векторе
 * С обработкой переполнения и пустого вектора
 */
uint64_t Calculator::calculateAverage(const std::vector<uint64_t>& vec) {
    if (vec.empty()) return 0;
    
    uint64_t sum = 0;
    // БЛОК: ВЫЧИСЛЕНИЕ СУММЫ С ПРОВЕРКОЙ ПЕРЕПОЛНЕНИЯ
    for (auto val : vec) {
        if (val > UINT64_MAX - sum) {
            return UINT64_MAX;  // Возвращаем максимум при переполнении
        }
        sum += val;
    }
    return sum / vec.size();
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА NETWORKUTILS
// ============================================================================

/**
 * Гарантированно читает все запрошенные данные из сокета
 * Работает в цикле пока не прочитает все len байт
 */
bool NetworkUtils::recvAll(int sock, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    // БЛОК: ЦИКЛИЧЕСКОЕ ЧТЕНИЕ ДО ЗАВЕРШЕНИЯ
    while (len > 0) {
        ssize_t received = recv(sock, p, len, 0);
        if (received <= 0) {
            return false;  // Ошибка или разрыв соединения
        }
        p += received;     // Сдвигаем указатель на прочитанные данные
        len -= received;   // Уменьшаем оставшийся размер
    }
    return true;
}

/**
 * Гарантированно отправляет все данные через сокет
 * Работает в цикле пока не отправит все len байт
 */
bool NetworkUtils::sendAll(int sock, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    // БЛОК: ЦИКЛИЧЕСКАЯ ОТПРАВКА ДО ЗАВЕРШЕНИЯ
    while (len > 0) {
        ssize_t sent = send(sock, p, len, 0);
        if (sent <= 0) {
            return false;  // Ошибка отправки
        }
        p += sent;         // Сдвигаем указатель на отправленные данные
        len -= sent;       // Уменьшаем оставшийся размер
    }
    return true;
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА CLIENTHANDLER
// ============================================================================

ClientHandler::ClientHandler(int client_sock, std::shared_ptr<UserManager> user_manager)
    : client_sock_(client_sock), user_manager_(user_manager) {}

/**
 * Основной метод обработки клиента
 * Управляет всем жизненным циклом соединения
 */
void ClientHandler::handle() {
    auto& logger = Logger::getInstance();
    
    // БЛОК 1: АУТЕНТИФИКАЦИЯ КЛИЕНТА
    if (!authenticate()) {
        logger.logError("Authentication failed for client", false);
        close(client_sock_);
        return;
    }
    
    // БЛОК 2: ОБРАБОТКА ДАННЫХ КЛИЕНТА
    if (!processData()) {
        logger.logError("Data processing failed for client", false);
        close(client_sock_);
        return;
    }
    
    // БЛОК 3: ЗАВЕРШЕНИЕ СОЕДИНЕНИЯ
    close(client_sock_);
    logger.logMessage("Connection closed for user: " + current_user_);
}

/**
 * Процесс аутентификации клиента по схеме с солью и хешем
 */
bool ClientHandler::authenticate() {
    auto& logger = Logger::getInstance();
    std::string login;
    
    // ЭТАП 1: ПОЛУЧЕНИЕ ЛОГИНА
    if (!receiveLogin(login)) {
        logger.logError("Failed to receive login", false);
        return false;
    }
    
    // ЭТАП 2: ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ
    if (!user_manager_->userExists(login)) {
        logger.logMessage("User not found: " + login);
        send(client_sock_, "ERR", 3, 0);
        return false;
    }
    
    // ЭТАП 3: ОТПРАВКА СОЛИ
    std::string salt = CryptoUtils::generateSalt();
    if (!sendSalt(salt)) {
        logger.logError("Failed to send salt", false);
        return false;
    }
    
    // ЭТАП 4: ПОЛУЧЕНИЕ И ПРОВЕРКА ХЕША
    std::string client_hash;
    if (!receiveHash(client_hash)) {
        logger.logError("Failed to receive hash", false);
        return false;
    }
    
    std::string password = user_manager_->getUserPassword(login);
    if (!verifyHash(salt, client_hash, password)) {
        logger.logMessage("Hash mismatch for user: " + login);
        send(client_sock_, "ERR", 3, 0);
        return false;
    }
    
    // ЭТАП 5: УСПЕШНАЯ АУТЕНТИФИКАЦИЯ
    send(client_sock_, "OK", 2, 0);
    current_user_ = login;
    logger.logMessage("Authentication successful for user: " + login);
    return true;
}

/**
 * Получает логин от клиента
 */
bool ClientHandler::receiveLogin(std::string& login) {
    char buffer[256];
    int len = recv(client_sock_, buffer, sizeof(buffer)-1, 0);
    if (len <= 0) {
        return false;
    }
    buffer[len] = '\0';
    login = CryptoUtils::trim(buffer);
    return true;
}

/**
 * Отправляет соль клиенту
 */
bool ClientHandler::sendSalt(const std::string& salt) {
    return NetworkUtils::sendAll(client_sock_, salt.c_str(), salt.size());
}

/**
 * Получает хеш от клиента
 */
bool ClientHandler::receiveHash(std::string& hash) {
    char buffer[256];
    int len = recv(client_sock_, buffer, sizeof(buffer)-1, 0);
    if (len <= 0) {
        return false;
    }
    buffer[len] = '\0';
    hash = CryptoUtils::trim(buffer);
    return true;
}

/**
 * Проверяет соответствие хеша от клиента ожидаемому значению
 */
bool ClientHandler::verifyHash(const std::string& salt, const std::string& client_hash, const std::string& password) {
    std::string server_hash = CryptoUtils::toUpper(CryptoUtils::sha224(salt + password));
    std::string upper_client_hash = CryptoUtils::toUpper(client_hash);
    return client_hash == server_hash;
}

/**
 * Обрабатывает данные от аутентифицированного клиента
 * Получает векторы чисел, вычисляет средние и возвращает результаты
 */
bool ClientHandler::processData() {
    auto& logger = Logger::getInstance();
    
    // БЛОК: ПОЛУЧЕНИЕ КОЛИЧЕСТВА ВЕКТОРОВ
    uint32_t num_vectors;
    if (!NetworkUtils::recvAll(client_sock_, &num_vectors, sizeof(num_vectors))) {
        logger.logError("Failed to receive number of vectors", false);
        return false;
    }
    
    // БЛОК: ОБРАБОТКА КАЖДОГО ВЕКТОРА
    for (uint32_t i = 0; i < num_vectors; i++) {
        // ПОДБЛОК 1: ПОЛУЧЕНИЕ РАЗМЕРА ВЕКТОРА
        uint32_t vec_size;
        if (!NetworkUtils::recvAll(client_sock_, &vec_size, sizeof(vec_size))) {
            logger.logError("Failed to receive vector size", false);
            return false;
        }
        
        // ПОДБЛОК 2: ПОЛУЧЕНИЕ ДАННЫХ ВЕКТОРА
        std::vector<uint64_t> vector(vec_size);
        if (vec_size > 0) {
            if (!NetworkUtils::recvAll(client_sock_, vector.data(), vec_size * sizeof(uint64_t))) {
                logger.logError("Failed to receive vector data", false);
                return false;
            }
        }
        
        // ПОДБЛОК 3: ВЫЧИСЛЕНИЕ И ОТПРАВКА РЕЗУЛЬТАТА
        uint64_t result = Calculator::calculateAverage(vector);
        if (!NetworkUtils::sendAll(client_sock_, &result, sizeof(result))) {
            logger.logError("Failed to send result", false);
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА SERVER
// ============================================================================

Server::Server() : server_sock_(-1), port_(0), running_(false) {
    user_manager_ = std::make_shared<UserManager>();
}

Server::~Server() {
    cleanup();
}

/**
 * Инициализирует сервер: парсит аргументы, настраивает логи, создает сокет
 */
bool Server::initialize(int argc, char* argv[]) {
    // БЛОК 1: ПАРСИНГ АРГУМЕНТОВ КОМАНДНОЙ СТРОКИ
    if (!parseArguments(argc, argv)) {
        return false;
    }
    
    auto& logger = Logger::getInstance();
    // БЛОК 2: НАСТРОЙКА СИСТЕМЫ ЛОГИРОВАНИЯ
    if (!logger.openLogFile(log_file_)) {
        std::cerr << "Cannot open log file" << std::endl;
        return false;
    }
    
    // БЛОК 3: ЗАГРУЗКА БАЗЫ ПОЛЬЗОВАТЕЛЕЙ
    if (!user_manager_->loadUsers(users_db_file_)) {
        logger.logError("Cannot open users file: " + users_db_file_, true);
        return false;
    }
    
    // БЛОК 4: СОЗДАНИЕ И НАСТРОЙКА СЕТЕВОГО СОКЕТА
    if (!createSocket()) {
        return false;
    }
    
    if (!setupAddress()) {
        return false;
    }
    
    if (!startListening()) {
        return false;
    }
    
    running_ = true;
    return true;
}

/**
 * Парсит аргументы командной строки
 */
bool Server::parseArguments(int argc, char* argv[]) {
    // БЛОК: ОБРАБОТКА ЗАПРОСА СПРАВКИ
    if (argc == 2 && std::string(argv[1]) == "-h") {
        std::cout << "Usage: " << argv[0] << " <users_db> <log_file> <port>" << std::endl;
        return false;
    }
    
    // БЛОК: ПРОВЕРКА КОЛИЧЕСТВА АРГУМЕНТОВ
    if (argc != 4) {
        std::cerr << "Invalid arguments. Use -h for help" << std::endl;
        return false;
    }
    
    users_db_file_ = argv[1];
    log_file_ = argv[2];
    port_ = std::stoi(argv[3]);
    return true;
}

/**
 * Создает и настраивает серверный сокет
 */
bool Server::createSocket() {
    auto& logger = Logger::getInstance();
    
    server_sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_ < 0) {
        logger.logError("Socket creation failed", true);
        return false;
    }
    
    // БЛОК: НАСТРОЙКА ПЕРЕИСПОЛЬЗОВАНИЯ АДРЕСА
    int opt = 1;
    setsockopt(server_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    return true;
}

/**
 * Настраивает адрес сервера и привязывает сокет
 */
bool Server::setupAddress() {
    auto& logger = Logger::getInstance();
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        logger.logError("Bind failed", true);
        return false;
    }
    
    return true;
}

/**
 * Переводит сокет в режим прослушивания
 */
bool Server::startListening() {
    auto& logger = Logger::getInstance();
    
    if (listen(server_sock_, 5) < 0) {
        logger.logError("Listen failed", true);
        return false;
    }
    
    logger.logMessage("Server started on port " + std::to_string(port_));
    return true;
}

/**
 * Основной цикл работы сервера - принимает и обрабатывает клиентов
 */
void Server::run() {
    auto& logger = Logger::getInstance();
    
    // БЛОК: ОСНОВНОЙ ЦИКЛ ОБРАБОТКИ СОЕДИНЕНИЙ
    while (running_) {
        int client_sock = accept(server_sock_, nullptr, nullptr);
        if (client_sock < 0) {
            logger.logError("Accept failed", false);
            continue;
        }
        
        logger.logMessage("New client connected");
        
        // БЛОК: СОЗДАНИЕ ОБРАБОТЧИКА ДЛЯ КАЖДОГО КЛИЕНТА
        // В реальном приложении здесь нужно использовать пул потоков
        ClientHandler client_handler(client_sock, user_manager_);
        client_handler.handle();
    }
}

void Server::stop() {
    running_ = false;
}

/**
 * Освобождает ресурсы сервера
 */
void Server::cleanup() {
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    Logger::getInstance().closeLogFile();
}

