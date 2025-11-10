#include "server.h"
#include <iostream>

/**
 * Точка входа в программу
 * Создает и запускает сервер с переданными параметрами
 */
int main(int argc, char* argv[]) {
    // БЛОК: СОЗДАНИЕ И ИНИЦИАЛИЗАЦИЯ СЕРВЕРА
    Server server;
    
    if (!server.initialize(argc, argv)) {
        return 1;  // Завершение с ошибкой если инициализация не удалась
    }
    
    // БЛОК: ЗАПУСК ОСНОВНОГО ЦИКЛА СЕРВЕРА
    server.run();
    
    return 0;
}
