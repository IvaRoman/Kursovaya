#include <cstring>
#include "server.h"
#include <iostream>
#include <fstream>
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

// Глобальные переменные
std::unordered_map<std::string, std::string> users;  // База пользователей (логин:пароль)
std::ofstream logfile;                               // Файл для записи логов

void log_error(const std::string& msg, bool critical) {
    time_t now = time(0);                           // Текущее время
    char* dt = ctime(&now);                         // Время в строку
    dt[strlen(dt)-1] = '\0';                        // Удаляем символ новой строки
    logfile << dt << " " << (critical ? "CRITICAL: " : "ERROR: ") << msg << std::endl;
    std::cout << "LOG: " << msg << std::endl;       // Дублируем в консоль
}

std::string generate_salt() {
    std::random_device rd;                          // Источник энтропии
    std::mt19937_64 gen(rd());                      // Генератор случайных чисел
    std::uniform_int_distribution<uint64_t> dis;    // Равномерное распределение
    uint64_t salt_val = dis(gen);                   // Случайное 64-битное число
    
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << salt_val;  // В hex формате
    return ss.str();
}

std::string sha224(const std::string& str) {
    unsigned char hash[SHA224_DIGEST_LENGTH];       // Буфер для хеша
    SHA224(reinterpret_cast<const unsigned char*>(str.c_str()), str.size(), hash);  // Вычисляем хеш
    
    std::stringstream ss;
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        // Преобразуем каждый байт в hex строку
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string to_upper(const std::string& str) {
    std::string result = str;
    // Преобразуем все символы в верхний регистр
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string trim(const std::string& str) {
    // Находим первый непробельный символ
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";      // Если строка пустая
    // Находим последний непробельный символ
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);      // Возвращаем обрезанную строку
}

bool load_users(const std::string& filename) {
    std::ifstream file(filename);                   // Открываем файл
    if(!file.is_open()) {
        log_error("Cannot open users file: " + filename, true);
        return false;
    }
    
    std::string line;
    while(std::getline(file, line)) {               // Читаем построчно
        line = trim(line);
        if(line.empty()) continue;                  // Пропускаем пустые строки
        
        size_t pos = line.find(':');                // Ищем разделитель
        if(pos != std::string::npos) {
            std::string user = trim(line.substr(0, pos));    // Логин до двоеточия
            std::string pass = trim(line.substr(pos + 1));   // Пароль после двоеточия
            users[user] = pass;                     // Добавляем в базу
            std::cout << "Loaded user: '" << user << "'" << std::endl;
        }
    }
    return true;
}

uint64_t calculate_average(const std::vector<uint64_t>& vec) {
    if(vec.empty()) return 0;                       // Защита от пустого вектора
    
    uint64_t sum = 0;
    for(auto val : vec) {
        if(val > UINT64_MAX - sum) {                // Проверка переполнения
            return UINT64_MAX;                      // Возвращаем максимум при переполнении
        }
        sum += val;                                 // Суммируем значения
    }
    return sum / vec.size();                        // Вычисляем среднее
}

bool recv_all(int sock, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);              // Указатель на буфер
    while(len > 0) {
        ssize_t received = recv(sock, p, len, 0);   // Получаем данные
        if(received <= 0) {
            return false;                           // Ошибка или разрыв соединения
        }
        p += received;                              // Сдвигаем указатель
        len -= received;                            // Уменьшаем оставшийся размер
    }
    return true;                                    // Все данные получены
}

bool send_all(int sock, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);  // Указатель на данные
    while(len > 0) {
        ssize_t sent = send(sock, p, len, 0);       // Отправляем данные
        if(sent <= 0) {
            return false;                           // Ошибка отправки
        }
        p += sent;                                  // Сдвигаем указатель
        len -= sent;                                // Уменьшаем оставшийся размер
    }
    return true;                                    // Все данные отправлены
}

void handle_client(int client_sock) {
    char buffer[256];                               // Буфер для текстовых данных

// === ФАЗА АУТЕНТИФИКАЦИИ ===
    
    // Получение логина
    int len = recv(client_sock, buffer, sizeof(buffer)-1, 0);
    if(len <= 0) {
        log_error("Failed to receive login", false);
        close(client_sock);
        return;
    }
    buffer[len] = '\0';                             // Завершаем строку
    std::string login = trim(buffer);
    std::cout << "Received login: " << login << std::endl;
    
    // Проверка существования пользователя
    if(users.find(login) == users.end()) {
        std::cout << "User not found: " << login << std::endl;
        send(client_sock, "ERR", 3, 0);             // Отправляем ошибку
        close(client_sock);
        return;
    }
    
    // Отправка соли
    std::string salt = generate_salt();
    std::cout << "Generated salt: " << salt << std::endl;
    if(!send_all(client_sock, salt.c_str(), salt.size())) {
        log_error("Failed to send salt", false);
        close(client_sock);
        return;
    }
    
    // Получение хэша
    len = recv(client_sock, buffer, sizeof(buffer)-1, 0);
    if(len <= 0) {
        log_error("Failed to receive hash", false);
        close(client_sock);
        return;
    }
    buffer[len] = '\0';
    std::string client_hash = trim(buffer);
    std::cout << "Received client hash: " << client_hash << std::endl;
    // Проверка хэша
    std::string server_hash = to_upper(sha224(salt + users[login]));
    client_hash = to_upper(client_hash);
    std::cout << "Computed server hash: " << server_hash << std::endl;
    
    if(client_hash != server_hash) {
        std::cout << "Hash mismatch!" << std::endl;
        send(client_sock, "ERR", 3, 0);
        close(client_sock);
        return;
    }
    
    // Аутентификация успешна
    send(client_sock, "OK", 2, 0);
    std::cout << "Authentication successful" << std::endl;
    
    // === ФАЗА ОБРАБОТКИ ДАННЫХ ===
    
    // Получаем количество векторов
    uint32_t num_vectors;
    if(!recv_all(client_sock, &num_vectors, sizeof(num_vectors))) {
        log_error("Failed to receive number of vectors", false);
        close(client_sock);
        return;
    }
    std::cout << "Number of vectors: " << num_vectors << std::endl;
    
    // Обрабатываем каждый вектор
    for(uint32_t i = 0; i < num_vectors; i++) {
        // Получаем размер текущего вектора
        uint32_t vec_size;
        if(!recv_all(client_sock, &vec_size, sizeof(vec_size))) {
            log_error("Failed to receive vector size", false);
            close(client_sock);
            return;
        }
        std::cout << "Vector " << i << " size: " << vec_size << std::endl;
        
        // Получаем данные вектора
        std::vector<uint64_t> vector(vec_size);
        if(vec_size > 0) {
            if(!recv_all(client_sock, vector.data(), vec_size * sizeof(uint64_t))) {
                log_error("Failed to receive vector data", false);
                close(client_sock);
                return;
            }
            // Выводим элементы для отладки
            for(uint32_t j = 0; j < vec_size; j++) {
                std::cout << "Vector element " << j << ": " << vector[j] << std::endl;
            }
        }
        
        // Вычисляем среднее арифметическое
        uint64_t result = calculate_average(vector);
        std::cout << "Calculated average: " << result << std::endl;
        
        // Отправляем результат обратно клиенту
        if(!send_all(client_sock, &result, sizeof(result))) {
            log_error("Failed to send result", false);
            close(client_sock);
            return;
        }
        std::cout << "Result sent for vector " << i << std::endl;
    }
    
    // Завершение сеанса
    close(client_sock);
    std::cout << "Connection closed" << std::endl;
}

