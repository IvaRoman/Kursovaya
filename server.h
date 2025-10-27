#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

// Глобальные переменные - база пользователей и файл логов
extern std::unordered_map<std::string, std::string> users;
extern std::ofstream logfile;

// Функции логирования
void log_error(const std::string& msg, bool critical);

// Функции аутентификации
std::string generate_salt();                    // Генерация случайной соли
std::string sha224(const std::string& str);     // Хеширование SHA-224
std::string to_upper(const std::string& str);   // Преобразование в верхний регистр
std::string trim(const std::string& str);       // Удаление пробелов

// Работа с пользователями
bool load_users(const std::string& filename);   // Загрузка базы пользователей

// Вычислительные функции
uint64_t calculate_average(const std::vector<uint64_t>& vec);  // Среднее арифметическое

// Сетевое взаимодействие
bool recv_all(int sock, void* buf, size_t len);  // Гарантированное чтение
bool send_all(int sock, const void* buf, size_t len);  // Гарантированная отправка
void handle_client(int client_sock);             // Обработка клиента

#endif
