#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "ole32.lib")

#include <Windows.h>
#include <TlHelp32.h>
#include <ObjBase.h>
#include <Netlistmgr.h>
#include <urlmon.h>
#include <comdef.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <fmt/format.h>
#include <string>
#include <sstream>

#include "xorstr.h"
#include "thread_pool.h"
#include "anti_bad.h"
#include "bsod.h"

// Definitions
#define _PTR_MAX_VALUE ((PVOID)0x000F000000000000)

// Static auth
bool g_auth_static = false;
std::string static_name = xorstr_("config.json");

// Auth
nlohmann::json g_auth_data;

// Version
std::string g_current_version = xorstr_("v1");
std::string g_version{};

// Game selection
nlohmann::json g_list;
std::string g_tag{};
std::string g_remembered_tag{};

// Download
std::filesystem::path g_path{};
std::string g_file_name{};
ULONGLONG g_time{};

// Utilities
constexpr bool is_valid_ptr(PVOID p)
{
    return (p >= (PVOID)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr;
}

void set_text_color(int color = 15)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console)
        SetConsoleTextAttribute(console, color);
}

void set_console_things(const char* title)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console)
    {
        SetConsoleTitleA(title);
        SetConsoleOutputCP(CP_UTF8);
    }
}

void clear_console()
{
#if defined _WIN32
    system(xorstr_("cls"));
    // clrscr(); // Including header file : conio.h
#elif defined (__LINUX__) || defined(__gnu_linux__) || defined(__linux__)
    system(xorstr_("clear"));
    // std::cout<< u8"\033[2J\033[1;1H"; // Using ANSI Escape Sequences 
#elif defined (__APPLE__)
    system(xorstr_("clear"));
#endif
}

// Structs
struct tag
{
    int col{};
    std::string str{};
};

struct games
{
    std::string num{};
    std::string tag{};
    std::string name{};
};

void pretty_print(const char* message, int color = 15, int disable_tag = 0, int add_space = 1)
{
    if (!disable_tag)
    {
        // Colored tag
        std::vector<tag> tag
        {
            { 5, xorstr_("[") },
            { 9, xorstr_("X") },
            { 5, xorstr_("]") }
        };

        int i = 0;
        for (const auto& rsc : tag)
        {
            i++;

            set_text_color(rsc.col);

            std::string st = rsc.str;
            if (i == tag.size())
                st += xorstr_(" ");

            printf(st.c_str());
        }
    }

    set_text_color(color);

    std::string format = message;
    if (add_space)
        format += xorstr_("\n");

    const char* converted = format.c_str();
    printf(converted);
}

std::filesystem::path temporary_directory()
{
    auto path = std::filesystem::path(std::getenv(xorstr_("appdata")));
    path /= xorstr_("Sixthworks");
    path /= xorstr_("Launcher");

    if (!std::filesystem::exists(path))
    {
        std::filesystem::create_directories(path);
    }
    else if (!std::filesystem::is_directory(path))
    {
        std::filesystem::remove(path);
        std::filesystem::create_directories(path);
    }

    return path;
}

void terminate(int delay)
{
    if (delay >= 0)
        std::this_thread::sleep_for(std::chrono::seconds(delay));

    TerminateProcess(GetCurrentProcess(), 0);
}

void throw_error(const char* error)
{
    pretty_print(error, 12);
    terminate(3);

    return;
}

enum class INTERNET_STATUS
{
    CONNECTED,
    DISCONNECTED,
    CONNECTED_TO_LOCAL,
    CONNECTION_ERROR
};

INTERNET_STATUS is_connected_to_internet()
{
    INTERNET_STATUS status = INTERNET_STATUS::CONNECTION_ERROR;
    HRESULT hr = S_FALSE;
    try
    {
        hr = CoInitialize(NULL);
        if (SUCCEEDED(hr))
        {
            INetworkListManager* network_manager;
            hr = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, __uuidof(INetworkListManager), (LPVOID*)&network_manager);
            
            if (SUCCEEDED(hr))
            {
                NLM_CONNECTIVITY connectivity = NLM_CONNECTIVITY::NLM_CONNECTIVITY_DISCONNECTED;
                VARIANT_BOOL is_connected = VARIANT_FALSE;

                hr = network_manager->get_IsConnectedToInternet(&is_connected);

                if (SUCCEEDED(hr))
                {
                    if (is_connected == VARIANT_TRUE)
                        status = INTERNET_STATUS::CONNECTED;
                    else
                        status = INTERNET_STATUS::DISCONNECTED;
                }

                if (is_connected == VARIANT_FALSE && SUCCEEDED(network_manager->GetConnectivity(&connectivity)))
                {
                    if (connectivity & (NLM_CONNECTIVITY_IPV4_LOCALNETWORK | NLM_CONNECTIVITY_IPV4_SUBNET | NLM_CONNECTIVITY_IPV6_LOCALNETWORK | NLM_CONNECTIVITY_IPV6_SUBNET))
                    {
                        status = INTERNET_STATUS::CONNECTED_TO_LOCAL;
                    }
                }

                network_manager->Release();
            }
        }

        CoUninitialize();
    }
    catch (...)
    {
        status = INTERNET_STATUS::CONNECTION_ERROR;
    }

    return status;
}

std::size_t callback(const char* in, std::size_t size, std::size_t num, std::string* out)
{
    const std::size_t totalBytes(size * num);
    out->append(in, totalBytes);
    return totalBytes;
}

std::size_t write_data(void* ptr, std::size_t size, std::size_t nmemb, FILE* stream) {
    std::size_t written;
    written = fwrite(ptr, size, nmemb, stream);
    return written;
}

void save_json(std::filesystem::path path, nlohmann::json json)
{
    std::ofstream rest(path, std::ios::out | std::ios::trunc);
    rest << json.dump(4);
    rest.close();
}

void get_auth_json(std::string username, std::string password, std::string game_tag)
{
    std::string site = xorstr_("http://localhost/backend/check.php?username=") + username + xorstr_("&password=") + password + xorstr_("&game=") + game_tag;
    std::string result;

    CURL* curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, xorstr_("GET"));
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    if (result.empty())
    {
        throw_error(xorstr_("Failed to parse auth."));
        return;
    }

    g_auth_data = nlohmann::json::parse(result);
}

void get_version()
{
    std::string site = xorstr_("http://localhost/backend/check_version.php");
    std::string result;

    CURL* curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, xorstr_("GET"));
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    if (result.empty())
    {
        throw_error(xorstr_("Failed to parse version."));
        return;
    }

    g_version = result;
}

void get_games()
{
    std::string site = xorstr_("http://localhost/backend/games_list.php");
    std::string result;
    
    CURL* curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, xorstr_("GET"));
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    if (result.empty())
    {
        throw_error(xorstr_("Failed to parse games list."));
        return;
    }

    g_list = nlohmann::json::parse(result);
}

int64_t get_current_timestamp()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::filesystem::path get_update_path()
{
    std::filesystem::path file_path = temporary_directory();
    file_path /= xorstr_("updates_data.json");

    return file_path;
}

std::string get_local_update_date()
{
    std::filesystem::path file_path = get_update_path();

    nlohmann::json json;
    std::ifstream file(file_path);

    if (!file.fail())
    {    
        file >> json;

        // We do this to validate if the user has this game's local time.
        std::string key{};
        for (auto& el : json.items())
        {
            if (el.key() == g_tag)
                key = el.key();
        }

        // If we got a result
        if (!key.empty())
        {
            int64_t timestamp = json[key][xorstr_("last_update")];
            std::string epoch = std::to_string(timestamp);

            if (!epoch.empty())
                return epoch;
        }
    }

    return xorstr_("");
}

// Ideally should be ran after the download function
void set_local_update_date()
{
    std::filesystem::path file_path = get_update_path();

    nlohmann::json json;
    std::ifstream file(file_path);

    if (!file.fail())
    {
        file >> json;

        // Update json
        json[g_tag][xorstr_("last_update")] = get_current_timestamp();

        // Create or update the file
        std::ofstream rest(file_path, std::ios::out | std::ios::trunc);
        rest << json.dump(4);
        rest.close();
    }
}

void get_bonzo()
{
    // Downloads folder + file name
    std::string site = xorstr_("http://localhost/backend/downloads/") + g_file_name;

    // File variable
    FILE* fp;

    // File request
    CURL* curl = curl_easy_init();
    if (curl)
    {
        ULONGLONG now = GetTickCount64();
        fp = fopen(g_path.string().c_str(), xorstr_("wb"));

        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);

        g_time = GetTickCount64() - now;
    }
    
    if (std::filesystem::exists(g_path))
    {
        set_local_update_date();
    }
    else
    {
        throw_error(xorstr_("Unfortunately the launcher failed to download the file, please contact the administrator."));
    }
}

void internet_check()
{
    INTERNET_STATUS status = is_connected_to_internet();
    switch (status)
    {
    case INTERNET_STATUS::DISCONNECTED:
    case INTERNET_STATUS::CONNECTED_TO_LOCAL:
    case INTERNET_STATUS::CONNECTION_ERROR:
        throw_error(xorstr_("Please connect to the internet before using the launcher."));
        break;
    }
}

void main_dbg_check()
{
    if (check_virtual() || cpu_debug_registers() || debug_string() || close_handle_exception() || write_buffer())
        blue_screen();

    if (is_sniffing())
        terminate(0);
}

DWORD process_id(std::string name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &ProcEntry)) {
        do
        {
            _bstr_t b(ProcEntry.szExeFile);
            const char* c = b;

            if (!strcmp(c, name.c_str()))
            {
                CloseHandle(hSnapshot);
                return ProcEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &ProcEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

HMODULE grab_module(DWORD process_id, std::string module_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return nullptr;

    MODULEENTRY32 ModEntry;
    if (Module32First(hSnapshot, &ModEntry))
    {
        do
        {
            _bstr_t b(ModEntry.szModule);
            const char* c = b;

            if (!strcmp(c, module_name.c_str()))
            {
                CloseHandle(hSnapshot);
                return HMODULE(ModEntry.modBaseAddr);
            }
        } while (Module32Next(hSnapshot, &ModEntry));
    }

    CloseHandle(hSnapshot);
    return nullptr;
}

bool is_answer_positive(std::string answer)
{
    std::vector <std::string> positive_answers
    {
        xorstr_("Ye"),
        xorstr_("ye"),
        xorstr_("Yea"),
        xorstr_("Yeah"),
        xorstr_("yea"),
        xorstr_("yeah"),
        xorstr_("yes"),
        xorstr_("Y"),
        xorstr_("y"),
        xorstr_("Yes"),
        xorstr_("YES"),
        xorstr_("yES"),
        xorstr_("1"),
        xorstr_("+"),
    };

    int hits = 0;
    for (const auto& rs : positive_answers)
    {
        if (answer == rs)
            hits++;
    }

    return hits > 0;
}

void run()
{
    // Variables
    std::string wait_for_process{};
    std::string desired_process{};
    
    // Get the process code to inject to
    int hits = 0;
    for (auto& el : g_list.items())
    {
        if (el.key() == g_tag)
        {
            std::string temp = g_list[g_tag][xorstr_("file_info")][xorstr_("process")];
            if (!temp.empty())
            {
                desired_process = temp;
                hits++;
            }
        }
    }

    // If something messed up
    if (hits <= 0)
        throw_error(xorstr_("Couldn't figure out which process the cheat should inject to. Consider contacting an administrator."));

    // Find the game process id
    DWORD id = process_id(desired_process);
    if (!id)
    {
        pretty_print(xorstr_("Game process was not found, do you want to wait for it? (Y/N): "));
        std::getline(std::cin, wait_for_process);

        // Clear the console, otherwise it would look ugly
        clear_console();

        // Figure out if we should wait
        if (is_answer_positive(wait_for_process))
        {
            // Animation ticks
            ULONGLONG ticks[] = { 0, 0 };
            ULONGLONG configuration[] = { 4000, 5000 };

            // Process placeholder
            DWORD placeholder = NULL;

            // Cool text
            std::string text = fmt::format(xorstr_("Waiting for {} to open"), desired_process);

            // Progress dots
            int dots = 0;
            int dots_max = 7; // Maximum amount of dots
            
            // First time?
            bool first_time = true;

            while (!placeholder)
            {
                // Current time
                ULONGLONG now = GetTickCount64();

                for (int i = 0; i < sizeof(configuration) / sizeof(*configuration); i++)
                {
                    if (now - ticks[i] > configuration[i])
                    {
                        switch (i)
                        {
                        case 1:
                        {
                            // Append value
                            placeholder = process_id(desired_process);
                        }
                        case 0:
                        {
                            if (first_time)
                            {
                                // Print out the text
                                pretty_print(text.c_str(), 15, 0, 0);

                                // Not the first time anymore
                                first_time = false;
                            }

                            // Maximum dots
                            if (dots >= dots_max)
                            {
                                // Clear the console
                                clear_console();

                                // Null them out
                                dots = 0;

                                // Print out the text
                                pretty_print(text.c_str(), 15, 0, 0);
                            }

                            // Add a dot to the string
                            printf(xorstr_("."));

                            dots++;
                        }
                        }

                        ticks[i] = now;
                    }
                }
            }

            // Assign the placeholder's value to our actual variable
            id = placeholder;

            // Clear the console before printing all the downloading/injecting stuff.
            clear_console();
        }
        else
        {
            throw_error(xorstr_("Game process was not found, terminating."));
        }
    }

    // Fill the empty variables with data
    g_file_name = g_list[g_tag][xorstr_("file_info")][xorstr_("name")];
    g_path = temporary_directory();
    g_path /= g_file_name;

    // Get the path
    std::filesystem::path update_path = get_update_path();

    // Do not allow the user to have the file without the update data
    if (std::filesystem::exists(g_path))
    {
        // Check if the update data doesn't exist
        if (!std::filesystem::exists(update_path))
        {
            // Delete the file
            std::filesystem::remove(g_path);

            // Empty json
            nlohmann::json json;

            // Create a dummy file
            save_json(update_path, json);
        }
    }

    // UNIX time
    std::string last_update = g_list[g_tag][xorstr_("last_update")];
    std::string local_last_update = get_local_update_date();

    // E.g if the latest updated occured later than the latest local update
    int last_update_int = std::stoi(last_update); // Can be 0, but this value is manual
    int local_last_update_int = local_last_update.empty() ? 0 : std::stoi(local_last_update); // Can be 0

    // Safe switch is to prevent a bug where user doesn't have the file, but has the JSON.
    bool safe_switch = false;
    while (true)
    {
        bool download = (last_update_int > local_last_update_int) || safe_switch;
        if (download)
        {
            // Print some info
            pretty_print(xorstr_("Downloading..."));

            // Get our file
            void(*tramp)();
            tramp = &get_bonzo;
            tramp();

            // Print out the time that took to download the cheat
            pretty_print(fmt::format(xorstr_("Downloaded in {} miliseconds."), g_time).c_str());

            break;
        }
        else
        {
            // If it doesn't exist, enable safe switch and cycle again.
            if (!std::filesystem::exists(g_path))
            {
                safe_switch = true;
            }
            else
            {
                pretty_print(xorstr_("File is up to date, using the existing one."));
                
                break;
            }
        }
    }

    // Check if it exists again
    if (std::filesystem::exists(g_path))
    {
        // Execution based on file type
        std::string type = g_list[g_tag][xorstr_("file_info")][xorstr_("type")];
        
        // Convert to int
        int type_f = std::stoi(type);
        
        switch (type_f)
        {
        case 1:
        {
            // Check if the dll is already injected into the game
            HMODULE module_grab = grab_module(id, g_path.filename().string());
            if (module_grab)
                throw_error(xorstr_("Software is already injected into the game."));

            // Open the process
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
            if (!process)
                throw_error(xorstr_("Failed to open the process."));

            // Allocate space in the process for the dll 
            LPVOID memory = LPVOID(VirtualAllocEx(process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!memory)
                throw_error(xorstr_("Failed to allocate memory in the process."));

            // Write the string name of our dll in the allocated memory
            if (!WriteProcessMemory(process, memory, g_path.string().c_str(), MAX_PATH, nullptr))
                throw_error(xorstr_("Failed to write in process's memory."));

            // Get the module
            HMODULE module_handle = GetModuleHandleA(xorstr_("kernel32.dll"));
            if (module_handle == INVALID_HANDLE_VALUE || !is_valid_ptr(module_handle))
                throw_error(xorstr_("Failed to get the kernel module handle."));

            // Get the LoadLibraryA adress
            FARPROC func_address = GetProcAddress(module_handle, xorstr_("LoadLibraryA"));
            if (!is_valid_ptr(func_address))
                throw_error(xorstr_("Failed to get the loadlibrary function address."));

            // Load the dll
            HANDLE thread = CreateRemoteThread(process, nullptr, NULL, LPTHREAD_START_ROUTINE(func_address), memory, NULL, nullptr);
            if (!thread)
                throw_error(xorstr_("Failed to create a remote thread."));

            // To make sure that our DLL is injected, we can use the following two calls to block program execution
            DWORD exit_code = 0;

            WaitForSingleObject(thread, INFINITE);
            GetExitCodeThread(thread, &exit_code);

            // Let the program regain control of itself
            CloseHandle(process);

            // Free the allocated memory.
            VirtualFreeEx(process, LPVOID(memory), 0, MEM_RELEASE);

            // Congratulate
            pretty_print(xorstr_("Injection success."));

            break;
        }
        case 2:
        {
            // Convert to the needed data-type
            _bstr_t b = g_path.string().c_str();

            // Execution
            ShellExecute(0, 0, b, 0, 0, SW_SHOWDEFAULT);

            // Congratulate
            pretty_print(xorstr_("Process started."));

            break;
        }
        default:
        {
            throw_error(xorstr_("Could not figure out how to start the cheat, please contact an administrator."));

            break;
        }
        }
    }
    else
    {
        throw_error(xorstr_("The needed file is not present, terminating."));
    }
}

int main()
{
    // Initialize thread pool
    auto thread_pool_instance = std::make_unique<thread_pool>();

    while (true)
    {
        // Protection
        g_thread_pool->push([&]
        {
            while (true)
            {
                void(*tramp)();
                tramp = &main_dbg_check;
                tramp();

                void(*tramp_1)();
                tramp_1 = &internet_check;
                tramp_1();
            }
        });

        // Custom window title
        set_console_things(xorstr_("Sixthworks"));

        // Will be used later
        int attempts{};

        // Version check
        {
            g_thread_pool->push([&]
            {
                void(*tramp)();
                tramp = &get_version;
                tramp();
            });
            
            while (g_version.empty())
            {
                if (attempts >= 10)
                {
                    throw_error(xorstr_("Getting the current version took too long, terminating."));
                    break;
                }

                attempts++;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            attempts = 0;

            // Version outdated check
            if (g_current_version != g_version)
            {
                throw_error(xorstr_("Your launcher version does not match the latest version, consider updating the launcher."));
            }
        }

        // Static
        nlohmann::json login_json;
        std::filesystem::path p_file = static_name;
        std::ifstream file(p_file);

        // Variables
        std::string username{};
        std::string password{};
        std::string game_choice{};
        std::string remember_choice{};

        if (!file.fail())
        {
            file >> login_json;
            
            // Username
            if (login_json.find(xorstr_("username")) != login_json.end())
            {
                username = login_json[xorstr_("username")];
            }
            else
            {
                throw_error(xorstr_("No username found in file."));
            }

            // Password
            if (login_json.find(xorstr_("password")) != login_json.end())
            {
                password = login_json[xorstr_("password")];
            }
            else
            {
                throw_error(xorstr_("No password found in file."));
            }

            // Game tag
            if (login_json.find(xorstr_("game_tag")) != login_json.end())
            {
                g_tag = login_json[xorstr_("game_tag")];
            }

            g_auth_static = true;
        }
        else
        {
            // Username input
            pretty_print(xorstr_("Username:"));
            std::getline(std::cin, username);

            // Password input
            pretty_print(xorstr_("Password:"));
            std::getline(std::cin, password);
        }

        // Game list
        {
            g_thread_pool->push([&]
            {
                void(*tramp)();
                tramp = &get_games;
                tramp();
            });

            while (g_list.empty())
            {
                if (attempts >= 10)
                {
                    throw_error(xorstr_("Getting the game information took too long, terminating."));
                    break;
                }

                attempts++;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            attempts = 0;
        }
        
        // Ask the user about his game choice
        if (g_tag.empty())
        {
            // Vector which needs to be filled
            std::vector<games> handler;

            // 1 newline at the beginning
            std::string to_print = xorstr_("\n");

            int i = 0;
            for (auto& el : g_list.items())
            {
                std::string num, name, tag;
                num = std::to_string(i + 1);
                name = g_list[el.key()][xorstr_("name")];
                tag  = el.key();

                // Fill vector with data
                games data;
                data.num = num;
                data.name = name;
                data.tag = tag;

                handler.push_back(data);

                // Append string
                to_print += xorstr_("") + num + xorstr_(": ") + name + xorstr_("\n");

                i++;
            }
            
            // Another one
            to_print += xorstr_("\n");
            to_print += xorstr_("Enter the game number which you are willing to play with the cheat: ");

            pretty_print(to_print.c_str(), 15, 0, 0);
            std::getline(std::cin, game_choice);

            // Print 1 extra symbol, the error message looks retarded if not this.
            printf(xorstr_("\n"));

            // Choosing the correct tag by value
            int hits = 0;
            for (const auto& rs : handler)
            {
                if (game_choice == rs.num)
                {
                    g_tag = rs.tag;
                    hits++;
                }
            }

            // Check if no hits
            if (hits <= 0)
                throw_error(xorstr_("Invalid game choice."));

            // Clear the console, because the number looks kinda bad above the text
            clear_console();
        }

        // Auth
        {
            g_thread_pool->push([&]
            {
                void(*tramp)(std::string, std::string, std::string);
                tramp = &get_auth_json;
                tramp(username, password, g_tag);
            });

            // Wait for auth to load
            while (g_auth_data.empty())
            {
                if (attempts >= 10)
                {
                    throw_error(xorstr_("Response from the auth was too long, terminating."));
                    break;
                }

                attempts++;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            attempts = 0;
        }

        // Scan the json
        if (g_auth_data.find(xorstr_("status")) != g_auth_data.end())
        {
            if (g_auth_data[xorstr_("status")] == xorstr_("success"))
            {
                // Ask the user if he wants the software to remember him
                if (!g_auth_static)
                {
                    pretty_print(xorstr_("Do you want the software to remember your choices? (Y/N): "));
                    std::getline(std::cin, remember_choice);

                    // If the user wrote a good answer
                    if (is_answer_positive(remember_choice))
                    {
                        // Json object
                        nlohmann::json json;
                        json[xorstr_("username")] = username;
                        json[xorstr_("password")] = password;
                        json[xorstr_("game_tag")] = g_tag;

                        // Save to json
                        save_json(p_file, json);
                    }
                }

                // Clear the console, we don't need any info on screen anymore
                clear_console();

                // Execute our hack
                run();

                // Wait 3 seconds and exit
                terminate(3);
            }
            else
            {
                if (g_auth_data.find(xorstr_("error")) != g_auth_data.end())
                {
                    if (g_auth_data[xorstr_("error")].is_string())
                    {
                        std::string error = g_auth_data[xorstr_("error")];
                        throw_error(error.c_str());
                    }
                    else
                    {
                        throw_error(xorstr_("Login failed."));
                    }
                }
                else
                {
                    throw_error(xorstr_("Login failed."));
                }
            }
        }
        else
        {
            throw_error(xorstr_("Failed getting status."));
        }

        terminate(0);
    }

    return -1;
}
