/**
 * \file server.cpp
 * \brief Реализация всех классов сервера
 * 
 * Содержит реализацию всех методов, объявленных в server.h.
 * Включает работу с сетью, криптографию, вычисления и логирование.
 * 
 * \note Для сборки требуется библиотека OpenSSL (-lssl -lcrypto)
 * 
 * \section network_protocol_sec Сетевой протокол
 * 
 * \subsection auth_subsec Аутентификация
 * 1. Клиент -> Сервер: логин
 * 2. Сервер -> Клиент: соль (16 байт в hex)
 * 3. Клиент вычисляет: hash = SHA224(соль + пароль)
 * 4. Клиент -> Сервер: hash (56 hex символов, верхний регистр)
 * 5. Сервер проверяет hash и отправляет "OK" или "ERR"
 * 
 * \subsection data_subsec Передача данных
 * 1. Клиент -> Сервер: количество векторов (uint32_t)
 * 2. Для каждого вектора:
 *    - Размер вектора (uint32_t)
 *    - Данные вектора (массив uint64_t)
 *    - Сервер -> Клиент: среднее значение (uint64_t)
 * 
 * \section limitations_sec Ограничения
 * - Максимальная длина логина: 255 символов
 * - Максимальное количество векторов: 1000
 * - Максимальный размер вектора: 1,000,000 элементов
 * - Размер backlog очереди: 5 соединений
 * - Таймаут приема данных: 5 секунд
 */

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

/**
 * \brief Получение единственного экземпляра Logger (Singleton)
 * \return Ссылка на единственный экземпляр класса Logger
 * 
 * \details Реализация шаблона Singleton. При первом вызове создает экземпляр,
 * при последующих возвращает существующий.
 */
Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

/**
 * \brief Открытие файла для записи логов
 * \param[in] filename Имя файла лога
 * \return true если файл успешно открыт, false в противном случае
 * 
 * \details Открывает файл в режиме добавления (append). Если файл не существует,
 * он будет создан. Если файл существует, новые записи добавляются в конец.
 */
bool Logger::openLogFile(const std::string& filename) {
    logfile_.open(filename, std::ios::app);
    return logfile_.is_open();
}

/**
 * \brief Запись сообщения об ошибке в лог
 * \param[in] msg Текст сообщения об ошибке
 * \param[in] critical Флаг критичности ошибки
 * 
 * \details Форматирует сообщение с временной меткой и уровнем критичности,
 * записывает в файл лога и выводит в консоль. Формат записи:
 * [Время] CRITICAL/ERROR: Сообщение
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
 * \brief Запись информационного сообщения в лог
 * \param[in] msg Текст информационного сообщения
 * 
 * \details Форматирует сообщение с временной меткой и уровнем INFO,
 * записывает в файл лога и выводит в консоль. Формат записи:
 * [Время] INFO: Сообщение
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
 * \brief Закрытие файла логов
 * 
 * \details Закрывает файловый поток лога. Если файл не был открыт,
 * метод не выполняет никаких действий.
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
 * \brief Загрузка пользователей из файла
 * \param[in] filename Имя файла с пользователями
 * \return true если файл успешно загружен, false в противном случае
 * 
 * \details Читает файл построчно, каждая строка в формате "логин:пароль".
 * Пустые строки и строки без символа ':' игнорируются.
 * Пробельные символы в начале и конце логина и пароля обрезаются.
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

/**
 * \brief Проверка существования пользователя
 * \param[in] username Имя пользователя для проверки
 * \return true если пользователь существует, false в противном случае
 * 
 * \details Ищет пользователя в хеш-таблице. Сложность O(1).
 */
bool UserManager::userExists(const std::string& username) const {
    return users_.find(username) != users_.end();
}

/**
 * \brief Получение пароля пользователя
 * \param[in] username Имя пользователя
 * \return Пароль пользователя или пустую строку если пользователь не найден
 * 
 * \details Возвращает пароль из хеш-таблицы. Если пользователь не найден,
 * возвращает пустую строку.
 */
std::string UserManager::getUserPassword(const std::string& username) const {
    auto it = users_.find(username);
    return (it != users_.end()) ? it->second : "";
}

/**
 * \brief Добавление нового пользователя
 * \param[in] username Имя пользователя
 * \param[in] password Пароль пользователя
 * 
 * \details Добавляет или обновляет запись пользователя в хеш-таблице.
 * Если пользователь уже существует, его пароль будет перезаписан.
 */
void UserManager::addUser(const std::string& username, const std::string& password) {
    users_[username] = password;
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА CRYPTOUTILS
// ============================================================================

/**
 * \brief Генерация случайной соли для хеширования
 * \return 16-байтная соль в hex-формате (32 символа)
 * 
 * \details Использует std::random_device для получения энтропии от ОС,
 * затем генерирует 64-битное случайное число и преобразует его в
 * hex-строку фиксированной длины (16 hex символов).
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
 * \brief Вычисление SHA-224 хеша от строки
 * \param[in] str Входная строка
 * \return Хеш в hex-формате (56 символов)
 * 
 * \details Использует библиотеку OpenSSL для вычисления SHA-224 хеша.
 * Результат преобразуется в строку hex-символов (0-9, a-f).
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
 * \brief Преобразование строки в верхний регистр
 * \param[in] str Входная строка
 * \return Строка в верхнем регистре
 * 
 * \details Использует std::transform с функцией ::toupper для преобразования
 * каждого символа строки в верхний регистр.
 */
std::string CryptoUtils::toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

/**
 * \brief Удаление пробельных символов с начала и конца строки
 * \param[in] str Входная строка
 * \return Обрезанная строка
 * 
 * \details Удаляет пробелы, табуляции, переводы строк и возвраты каретки
 * с начала и конца строки. Если строка состоит только из пробельных символов,
 * возвращает пустую строку.
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
 * \brief Вычисление среднего арифметического значений в векторе
 * \param[in] vec Вектор значений типа uint64_t
 * \return Среднее значение или UINT64_MAX при переполнении
 * 
 * \details Вычисляет сумму всех элементов вектора с проверкой переполнения.
 * Если происходит переполнение, возвращает UINT64_MAX.
 * Для пустого вектора возвращает 0.
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
 * \brief Гарантированное чтение всех запрошенных данных из сокета
 * \param[in] sock Дескриптор сокета
 * \param[out] buf Буфер для приема данных
 * \param[in] len Количество байт для чтения
 * \return true если все данные успешно прочитаны, false при ошибке
 * 
 * \details Вызывает recv() в цикле до тех пор, пока не будут прочитаны
 * все запрошенные байты. Возвращает false при ошибке или разрыве соединения.
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
 * \brief Гарантированная отправка всех данных через сокет
 * \param[in] sock Дескриптор сокета
 * \param[in] buf Буфер с данными для отправки
 * \param[in] len Количество байт для отправки
 * \return true если все данные успешно отправлены, false при ошибке
 * 
 * \details Вызывает send() в цикле до тех пор, пока не будут отправлены
 * все запрошенные байты. Возвращает false при ошибке отправки.
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

/**
 * \brief Конструктор обработчика клиента
 * \param[in] client_sock Дескриптор клиентского сокета
 * \param[in] user_manager Указатель на менеджер пользователей
 * 
 * \details Сохраняет дескриптор сокета и указатель на менеджер пользователей.
 * Инициализирует текущего пользователя пустой строкой.
 */
ClientHandler::ClientHandler(int client_sock, std::shared_ptr<UserManager> user_manager)
    : client_sock_(client_sock), user_manager_(user_manager) {}

/**
 * \brief Основной метод обработки клиента
 * 
 * \details Управляет всем жизненным циклом соединения:
 * 1. Аутентификация клиента
 * 2. Обработка данных от клиента
 * 3. Закрытие соединения и логирование
 * 
 * В случае ошибки на любом этапе соединение закрывается.
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
 * \brief Процесс аутентификации клиента
 * \return true если аутентификация успешна, false в противном случае
 * 
 * \details Выполняет пятиэтапную аутентификацию:
 * 1. Получение логина от клиента
 * 2. Проверка существования пользователя
 * 3. Генерация и отправка соли
 * 4. Получение и проверка хеша
 * 5. Отправка результата аутентификации
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
 * \brief Обработка данных от аутентифицированного клиента
 * \return true если обработка успешна, false в противном случае
 * 
 * \details Получает векторы чисел, вычисляет средние и возвращает результаты.
 * Выполняет валидацию входных данных:
 * - Максимум 1000 векторов
 * - Максимум 1,000,000 элементов в векторе
 * - Таймаут 5 секунд на прием данных
 */
bool ClientHandler::processData() {
    auto& logger = Logger::getInstance();
    
    // Получаем количество векторов
    uint32_t num_vectors;
    if (!NetworkUtils::recvAll(client_sock_, &num_vectors, sizeof(num_vectors))) {
        logger.logError("Failed to receive number of vectors", false);
        return false;
    }
    
    // ВАЛИДАЦИЯ: Проверяем разумность размера
    if (num_vectors > 1000) { // Максимум 1000 векторов
        logger.logError("Too many vectors: " + std::to_string(num_vectors), false);
        const char* err_msg = "ERR_TOO_MANY";
        send(client_sock_, err_msg, strlen(err_msg), 0);
        return false;
    }
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        uint32_t vec_size;
        if (!NetworkUtils::recvAll(client_sock_, &vec_size, sizeof(vec_size))) {
            logger.logError("Failed to receive vector size", false);
            return false;
        }
        
        // ВАЛИДАЦИЯ: Проверяем разумность размера вектора
        if (vec_size > 1000000) { // Максимум 1 млн элементов
            logger.logError("Vector too large: " + std::to_string(vec_size), false);
            const char* err_msg = "ERR_SIZE";
            send(client_sock_, err_msg, strlen(err_msg), 0);
            return false;
        }
        
        // ВАЛИДАЦИЯ: Если vec_size = 0, пропускаем
        if (vec_size == 0) {
            uint64_t result = 0;
            if (!NetworkUtils::sendAll(client_sock_, &result, sizeof(result))) {
                logger.logError("Failed to send result for empty vector", false);
                return false;
            }
            continue;
        }
        
        std::vector<uint64_t> vector(vec_size);
        
        // Пытаемся получить данные с таймаутом
        if (!receiveWithTimeout(vector.data(), vec_size * sizeof(uint64_t))) {
            logger.logError("Failed to receive vector data (timeout or invalid data)", false);
            const char* err_msg = "ERR_DATA";
            send(client_sock_, err_msg, strlen(err_msg), 0);
            return false;
        }
        
        uint64_t result = Calculator::calculateAverage(vector);
        if (!NetworkUtils::sendAll(client_sock_, &result, sizeof(result))) {
            logger.logError("Failed to send result", false);
            return false;
        }
    }
    
    return true;
}

/**
 * \brief Получение логина от клиента
 * \param[out] login Полученный логин
 * \return true если логин успешно получен, false в противном случае
 * 
 * \details Читает до 255 байт из сокета, добавляет нуль-терминатор
 * и обрезает пробельные символы.
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
 * \brief Отправка соли клиенту
 * \param[in] salt Соль для отправки
 * \return true если соль успешно отправлена, false в противном случае
 * 
 * \details Использует NetworkUtils::sendAll для гарантированной отправки.
 */
bool ClientHandler::sendSalt(const std::string& salt) {
    return NetworkUtils::sendAll(client_sock_, salt.c_str(), salt.size());
}

/**
 * \brief Получение хеша от клиента
 * \param[out] hash Полученный хеш
 * \return true если хеш успешно получен, false в противном случае
 * 
 * \details Читает до 255 байт из сокета, добавляет нуль-терминатор
 * и обрезает пробельные символы.
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
 * \brief Проверка соответствия хеша от клиента
 * \param[in] salt Соль, отправленная клиенту
 * \param[in] client_hash Хеш, полученный от клиента
 * \param[in] password Пароль пользователя из БД
 * \return true если хеши совпадают, false в противном случае
 * 
 * \details Вычисляет ожидаемый хеш как SHA224(соль + пароль) в верхнем регистре
 * и сравнивает с полученным от клиента хешом (также в верхнем регистре).
 * 
 * \note Клиент должен отправлять хеш в ВЕРХНЕМ регистре.
 */
bool ClientHandler::verifyHash(const std::string& salt, const std::string& client_hash, const std::string& password) {
    std::string server_hash = CryptoUtils::toUpper(CryptoUtils::sha224(salt + password));
    std::string upper_client_hash = CryptoUtils::toUpper(client_hash);
    return client_hash == server_hash;
}

/**
 * \brief Прием данных с таймаутом
 * \param[out] buf Буфер для приема данных
 * \param[in] len Количество байт для приема
 * \param[in] timeout_sec Таймаут в секундах (по умолчанию 5)
 * \return true если данные успешно получены, false при таймауте или ошибке
 * 
 * \details Временно устанавливает таймаут на сокете, получает данные,
 * затем восстанавливает оригинальные настройки таймаута.
 */
bool ClientHandler::receiveWithTimeout(void* buf, size_t len, int timeout_sec) {
    // Сохраняем текущие настройки сокета
    struct timeval original_tv;
    socklen_t optlen = sizeof(original_tv);
    getsockopt(client_sock_, SOL_SOCKET, SO_RCVTIMEO, &original_tv, &optlen);
    
    // Устанавливаем таймаут на сокет
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(client_sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    bool result = NetworkUtils::recvAll(client_sock_, buf, len);
    
    // Восстанавливаем оригинальные настройки
    setsockopt(client_sock_, SOL_SOCKET, SO_RCVTIMEO, &original_tv, sizeof(original_tv));
    
    return result;
}

// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА SERVER
// ============================================================================

/**
 * \brief Конструктор сервера
 * 
 * \details Инициализирует дескриптор сокета значением -1,
 * порт значением 0, создает shared_ptr на UserManager
 * и устанавливает флаг работы в false.
 */
Server::Server() : server_sock_(-1), port_(0), running_(false) {
    user_manager_ = std::make_shared<UserManager>();
}

/**
 * \brief Деструктор сервера
 * 
 * \details Вызывает cleanup() для освобождения ресурсов.
 */
Server::~Server() {
    cleanup();
}

/**
 * \brief Инициализация сервера
 * \param[in] argc Количество аргументов командной строки
 * \param[in] argv Массив аргументов командной строки
 * \return true если инициализация успешна, false в противном случае
 * 
 * \details Выполняет последовательную инициализацию:
 * 1. Парсинг аргументов командной строки
 * 2. Настройка системы логирования
 * 3. Загрузка базы пользователей
 * 4. Создание и настройка сетевого сокета
 * 5. Запуск прослушивания порта
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
 * \brief Парсинг аргументов командной строки
 * \param[in] argc Количество аргументов
 * \param[in] argv Массив аргументов
 * \return true если аргументы корректны, false в противном случае
 * 
 * \details Ожидает ровно 3 аргумента:
 * 1. Файл с пользователями
 * 2. Файл лога
 * 3. Порт (число от 1 до 65535)
 * 
 * Также обрабатывает флаг -h для вывода справки.
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
 * \brief Создание и настройка серверного сокета
 * \return true если сокет успешно создан, false в противном случае
 * 
 * \details Создает TCP-сокет (AF_INET, SOCK_STREAM) и настраивает
 * опцию SO_REUSEADDR для возможности повторного использования адреса.
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
 * \brief Настройка адреса сервера и привязка сокета
 * \return true если привязка успешна, false в противном случае
 * 
 * \details Настраивает структуру sockaddr_in для прослушивания
 * всех интерфейсов (INADDR_ANY) на указанном порту и привязывает сокет.
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
 * \brief Перевод сокета в режим прослушивания
 * \return true если успешно, false в противном случае
 * 
 * \details Устанавливает максимальный размер очереди ожидающих соединений
 * (backlog) равным 5. Это означает, что сервер может держать в очереди
 * до 5 полностью установленных соединений, ожидающих accept().
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
 * \brief Основной цикл работы сервера
 * 
 * \details Бесконечно ожидает входящие соединения через accept(),
 * создает ClientHandler для каждого подключившегося клиента
 * и синхронно обрабатывает его запросы.
 * 
 * \warning В текущей реализации сервер однопоточный и обрабатывает
 * клиентов последовательно. Для одновременной обработки нескольких
 * клиентов требуется модификация.
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

/**
 * \brief Остановка сервера
 * 
 * \details Устанавливает флаг running_ в false, что приводит
 * к завершению основного цикла в методе run().
 */
void Server::stop() {
    running_ = false;
}

/**
 * \brief Освобождение ресурсов сервера
 * 
 * \details Закрывает серверный сокет и файл логов.
 * Вызывается автоматически из деструктора.
 */
void Server::cleanup() {
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    Logger::getInstance().closeLogFile();
}
