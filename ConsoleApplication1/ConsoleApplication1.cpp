

#include <windows.h>
#include <iostream>
#include <cstring>

int main()
{
    size_t size = 256;
    char* allocatedMemory = nullptr;

    // Виділення пам'яті за допомогою VirtualAlloc
    allocatedMemory = (char*)VirtualAlloc(
        nullptr,       // Початок пам'яті (nullptr для динамічного розподілу)
        size,           // Розмір пам'яті
        MEM_COMMIT | MEM_RESERVE, // COMMIT означає виділення фізичної пам'яті
        PAGE_READWRITE   // Режим доступу: читання/запис
    );

    if (allocatedMemory == nullptr) {
        std::cerr << "Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Заповнення пам'яті даними
    strcpy_s(allocatedMemory, size, "Hello, VirtualAlloc!");

    // Читання даних з виділеної пам'яті
    std::cout << "Read from allocated memory: " << allocatedMemory << std::endl;

    // Звільнення пам'яті
    if (VirtualFree(allocatedMemory, 0, MEM_RELEASE) == 0) {
        std::cerr << "Failed to free memory. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Memory successfully freed." << std::endl;

    return 0;
}


