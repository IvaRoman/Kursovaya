/**
 * \file server.h
 * \brief Основной заголовочный файл сервера
 * 
 * Содержит объявления всех классов сервера для обработки клиентских соединений,
 * аутентификации пользователей, вычислений и сетевых операций.
 * 
 * \mainpage Сервер обработки векторных данных
 * \section intro_sec Введение
 * Сервер предназначен для безопасной обработки векторных данных от клиентов.
 * Обеспечивает:
 * - Аутентификацию по схеме с солью и SHA-224 хешем
 * - Обработку векторов чисел типа uint64_t
 * - Вычисление среднего арифметического
 * - Логирование всех операций
 * - Устойчивую работу при множественных подключениях
 * 
 * \section arch_sec Архитектура
 * Сервер использует следующие компоненты:
 * - Logger - система логирования (Singleton)
 * - UserManager - управление пользователями
 * - CryptoUtils - криптографические операции
 * - Calculator - математические вычисления
 * - NetworkUtils - сетевые операции
 * - ClientHandler - обработчик клиента
 * - Server - основной класс сервера
 * 
 * \section protocol_sec Протокол обмена
 * 1. Клиент отправляет логин
 * 2. Сервер генерирует и отправляет соль
 * 3. Клиент вычисляет SHA224(соль + пароль)
 * 4. Сервер проверяет хеш
 * 5. Клиент отправляет векторы данных
 * 6. Сервер вычисляет и возвращает средние значения
 */

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
 * \class Logger
 * \brief Класс для управления системой логирования (шаблон Singleton)
 * 
 * Обеспечивает запись логов в файл и консоль с временными метками.
 * Поддерживает два типа сообщений: ошибки и информационные.
 */
class Logger {
public:
    /**
     * \brief Получение единственного экземпляра Logger
     * \return Ссылка на единственный экземпляр класса
     */
    static Logger& getInstance();
    
    /**
     * \brief Открытие файла для записи логов
     * \param[in] filename Имя файла лога
     * \return true если файл успешно открыт, false в противном случае
     */
    bool openLogFile(const std::string& filename);
    
    /**
     * \brief Запись сообщения об ошибке в лог
     * \param[in] msg Текст сообщения
     * \param[in] critical Флаг критичности ошибки
     */
    void logError(const std::string& msg, bool critical);
    
    /**
     * \brief Запись информационного сообщения в лог
     * \param[in] msg Текст сообщения
     */
    void logMessage(const std::string& msg);
    
    /**
     * \brief Закрытие файла логов
     */
    void closeLogFile();

private:
    Logger() = default; ///< Приватный конструктор для Singleton
    std::ofstream logfile_; ///< Поток для записи в файл лога
};

/**
 * \class UserManager
 * \brief Класс для управления базой пользователей
 * 
 * Загружает пользователей из файла, проверяет существование, хранит пароли.
 * Формат файла: "логин:пароль" на каждой строке.
 */
class UserManager {
public:
    /**
     * \brief Загрузка пользователей из файла
     * \param[in] filename Имя файла с пользователями
     * \return true если файл успешно загружен, false в противном случае
     */
    bool loadUsers(const std::string& filename);
    
    /**
     * \brief Проверка существования пользователя
     * \param[in] username Имя пользователя для проверки
     * \return true если пользователь существует, false в противном случае
     */
    bool userExists(const std::string& username) const;
    
    /**
     * \brief Получение пароля пользователя
     * \param[in] username Имя пользователя
     * \return Пароль пользователя или пустую строку если пользователь не найден
     */
    std::string getUserPassword(const std::string& username) const;
    
    /**
     * \brief Добавление нового пользователя
     * \param[in] username Имя пользователя
     * \param[in] password Пароль пользователя
     */
    void addUser(const std::string& username, const std::string& password);

private:
    std::unordered_map<std::string, std::string> users_; ///< Хранилище пользователей
};

/**
 * \class CryptoUtils
 * \brief Утилитарный класс для криптографических операций
 * 
 * Содержит статические методы для работы с солями, хешами и строками.
 * Все методы статические - создание экземпляра класса не требуется.
 */
class CryptoUtils {
public:
    /**
     * \brief Генерация случайной соли для хеширования
     * \return 16-байтная соль в hex-формате
     */
    static std::string generateSalt();
    
    /**
     * \brief Вычисление SHA-224 хеша от строки
     * \param[in] str Входная строка
     * \return Хеш в hex-формате (56 символов)
     */
    static std::string sha224(const std::string& str);
    
    /**
     * \brief Преобразование строки в верхний регистр
     * \param[in] str Входная строка
     * \return Строка в верхнем регистре
     */
    static std::string toUpper(const std::string& str);
    
    /**
     * \brief Удаление пробельных символов с начала и конца строки
     * \param[in] str Входная строка
     * \return Обрезанная строка
     */
    static std::string trim(const std::string& str);
};

/**
 * \class Calculator
 * \brief Класс для математических вычислений
 * 
 * Содержит алгоритмы обработки числовых данных.
 * Все методы статические.
 */
class Calculator {
public:
    /**
     * \brief Вычисление среднего арифметического значений в векторе
     * \param[in] vec Вектор значений типа uint64_t
     * \return Среднее значение или UINT64_MAX при переполнении
     * \note Для пустого вектора возвращается 0
     */
    static uint64_t calculateAverage(const std::vector<uint64_t>& vec);
};

/**
 * \class NetworkUtils
 * \brief Класс для низкоуровневых сетевых операций
 * 
 * Обеспечивает гарантированную отправку и прием данных через сокеты.
 * Все методы статические.
 */
class NetworkUtils {
public:
    /**
     * \brief Гарантированное чтение всех запрошенных данных из сокета
     * \param[in] sock Дескриптор сокета
     * \param[out] buf Буфер для приема данных
     * \param[in] len Количество байт для чтения
     * \return true если все данные успешно прочитаны, false при ошибке
     */
    static bool recvAll(int sock, void* buf, size_t len);
    
    /**
     * \brief Гарантированная отправка всех данных через сокет
     * \param[in] sock Дескриптор сокета
     * \param[in] buf Буфер с данными для отправки
     * \param[in] len Количество байт для отправки
     * \return true если все данные успешно отправлены, false при ошибке
     */
    static bool sendAll(int sock, const void* buf, size_t len);
};

/**
 * \class ClientHandler
 * \brief Класс для обработки индивидуального клиентского соединения
 * 
 * Управляет всей логикой взаимодействия с одним клиентом:
 * аутентификацией, приемом данных, вычислениями и отправкой результатов.
 */
class ClientHandler {
public:
    /**
     * \brief Конструктор обработчика клиента
     * \param[in] client_sock Дескриптор клиентского сокета
     * \param[in] user_manager Указатель на менеджер пользователей
     */
    ClientHandler(int client_sock, std::shared_ptr<UserManager> user_manager);
    
    /**
     * \brief Основной метод обработки клиента
     * 
     * Управляет всем жизненным циклом соединения:
     * 1. Аутентификация
     * 2. Обработка данных
     * 3. Закрытие соединения
     */
    void handle();

private:
    /**
     * \brief Процесс аутентификации клиента
     * \return true если аутентификация успешна, false в противном случае
     */
    bool authenticate();
    
    /**
     * \brief Обработка данных от аутентифицированного клиента
     * \return true если обработка успешна, false в противном случае
     */
    bool processData();
    
    /**
     * \brief Получение логина от клиента
     * \param[out] login Полученный логин
     * \return true если логин успешно получен, false в противном случае
     */
    bool receiveLogin(std::string& login);
    
    /**
     * \brief Отправка соли клиенту
     * \param[in] salt Соль для отправки
     * \return true если соль успешно отправлена, false в противном случае
     */
    bool sendSalt(const std::string& salt);
    
    /**
     * \brief Получение хеша от клиента
     * \param[out] hash Полученный хеш
     * \return true если хеш успешно получен, false в противном случае
     */
    bool receiveHash(std::string& hash);
    
    /**
     * \brief Проверка соответствия хеша от клиента
     * \param[in] salt Соль, отправленная клиенту
     * \param[in] client_hash Хеш, полученный от клиента
     * \param[in] password Пароль пользователя из БД
     * \return true если хеши совпадают, false в противном случае
     */
    bool verifyHash(const std::string& salt, const std::string& client_hash, 
                   const std::string& password);
    
    /**
     * \brief Прием данных с таймаутом
     * \param[out] buf Буфер для приема данных
     * \param[in] len Количество байт для приема
     * \param[in] timeout_sec Таймаут в секундах (по умолчанию 5)
     * \return true если данные успешно получены, false при таймауте или ошибке
     */
    bool receiveWithTimeout(void* buf, size_t len, int timeout_sec = 5);
    
    int client_sock_; ///< Дескриптор клиентского сокета
    std::shared_ptr<UserManager> user_manager_; ///< Менеджер пользователей
    std::string current_user_; ///< Текущий аутентифицированный пользователь
};

/**
 * \class Server
 * \brief Главный класс сервера
 * 
 * Управляет инициализацией, настройкой и основным циклом работы сервера.
 * Обрабатывает входящие подключения и создает ClientHandler для каждого клиента.
 */
class Server {
public:
    /**
     * \brief Конструктор сервера
     */
    Server();
    
    /**
     * \brief Деструктор сервера
     */
    ~Server();
    
    /**
     * \brief Инициализация сервера
     * \param[in] argc Количество аргументов командной строки
     * \param[in] argv Массив аргументов командной строки
     * \return true если инициализация успешна, false в противном случае
     */
    bool initialize(int argc, char* argv[]);
    
    /**
     * \brief Запуск основного цикла сервера
     */
    void run();
    
    /**
     * \brief Остановка сервера
     */
    void stop();

private:
    /**
     * \brief Парсинг аргументов командной строки
     * \param[in] argc Количество аргументов
     * \param[in] argv Массив аргументов
     * \return true если аргументы корректны, false в противном случае
     */
    bool parseArguments(int argc, char* argv[]);
    
    /**
     * \brief Создание и настройка серверного сокета
     * \return true если сокет успешно создан, false в противном случае
     */
    bool createSocket();
    
    /**
     * \brief Настройка адреса сервера и привязка сокета
     * \return true если привязка успешна, false в противном случае
     */
    bool setupAddress();
    
    /**
     * \brief Перевод сокета в режим прослушивания
     * \return true если успешно, false в противном случае
     */
    bool startListening();
    
    /**
     * \brief Освобождение ресурсов сервера
     */
    void cleanup();
    
    int server_sock_; ///< Дескриптор серверного сокета
    int port_; ///< Порт сервера
    std::string users_db_file_; ///< Имя файла с пользователями
    std::string log_file_; ///< Имя файла лога
    std::shared_ptr<UserManager> user_manager_; ///< Менеджер пользователей
    bool running_; ///< Флаг работы сервера
};
