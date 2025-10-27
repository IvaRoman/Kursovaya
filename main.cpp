#include "server.h"
#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // Проверка аргументов командной строки
    if(argc == 2 && std::string(argv[1]) == "-h") {
        std::cout << "Usage: " << argv[0] << " <users_db> <log_file> <port>" << std::endl;
        return 0;
    }
    
    if(argc != 4) {
        std::cerr << "Invalid arguments. Use -h for help" << std::endl;
        return 1;
    }
    
    // Открытие файла логов
    logfile.open(argv[2], std::ios::app);
    if(!logfile.is_open()) {
        std::cerr << "Cannot open log file" << std::endl;
        return 1;
    }
    
    // Загрузка базы пользователей
    if(!load_users(argv[1])) {
        return 1;
    }
    
    // Создание сокета
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0) {
        log_error("Socket creation failed", true);
        return 1;
    }
    
    // Разрешаем переиспользование адреса
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Настройка адреса сервера
    sockaddr_in addr{};
    addr.sin_family = AF_INET;                      // IPv4
    addr.sin_port = htons(std::stoi(argv[3]));      // Порт из аргументов
    addr.sin_addr.s_addr = INADDR_ANY;              // Все интерфейсы
    
    // Привязка сокета к адресу
    if(bind(server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Bind failed", true);
        return 1;
    }
    
    // Начало прослушивания
    if(listen(server_sock, 5) < 0) {
        log_error("Listen failed", true);
        return 1;
    }
    
    std::cout << "Server started on port " << argv[3] << std::endl;
    
    // Основной цикл сервера
    while(true) {
        // Принимаем входящее соединение
        int client_sock = accept(server_sock, nullptr, nullptr);
        if(client_sock < 0) {
            log_error("Accept failed", false);
            continue;                               // Продолжаем при ошибке
        }
        std::cout << "New client connected" << std::endl;
        handle_client(client_sock);                 // Обрабатываем клиента
    }
    
    close(server_sock);
    return 0;
}
