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
#include <random>

#include "globals.hpp"
#include "xorstr.hpp"
#include "thread_pool.hpp"
#include "protection.hpp"
#include "bsod.hpp"

// Color
void set_text_color(int color = 15)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console)
    {
        SetConsoleTextAttribute(console, color);
    }
}

// Indicator
void set_console_indicator(bool draw)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console)
    {
        // Cursor
        CONSOLE_CURSOR_INFO info;

        GetConsoleCursorInfo(console, &info);

        // Draw
        info.bVisible = draw;

        SetConsoleCursorInfo(console, &info);
    }
}

// Title
void set_console_things(const char* title)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console)
    {
        // Title
        SetConsoleTitleA(title);

        // Charset
        SetConsoleOutputCP(CP_UTF8);
    }
}

// Clear
void clear_console()
{
    system(xorstr_("cls"));
}

// Log
void pretty_print(const char* message, int color = 15, int disable_tag = 0, int add_newline = 1)
{
    if (!disable_tag)
    {
        // Struct
        struct tag_s
        {
            int color;

            std::string character;
        };

        // Configuration
        std::vector<tag_s> tag
        {
            { 5, xorstr_("[") },
            { 9, xorstr_("X") },
            { 5, xorstr_("]") },
        };

        // Creation
        for (const auto& rs : tag)
        {
            // Color
            set_text_color(rs.color);

            // Print
            printf(rs.character.c_str());
        }

        // Space
        printf(xorstr_(" "));
    }

    // Reset
    set_text_color(color);

    // Print
    printf(message);

    // Newline
    if (add_newline)
        printf(xorstr_("\n"));
}

// Validator
void validate_path(std::filesystem::path path, bool multiple_directories)
{
    if (!std::filesystem::exists(path))
    {
        multiple_directories ? std::filesystem::create_directory(path) : std::filesystem::create_directories(path);
    }
    else if (!std::filesystem::is_directory(path))
    {
        std::filesystem::remove(path);
        multiple_directories ? std::filesystem::create_directory(path) : std::filesystem::create_directories(path);
    }
}

// Worker
std::filesystem::path temporary_directory()
{
    auto path = std::filesystem::path(std::getenv(xorstr_("appdata")));
    path /= xorstr_("Sixthworks");
    path /= xorstr_("Launcher");

    validate_path(path, true);

    return path;
}

// Administrator rights
bool is_elevated()
{
    BOOL result = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            result = elevation.TokenIsElevated;
        }
    }

    if (token)
        CloseHandle(token);

    return result;
}

// Random
std::string random_string(int amount)
{
    std::string str(xorstr_("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));

    std::random_device rd;
    std::mt19937 generator(rd());

    std::shuffle(str.begin(), str.end(), generator);

    return str.substr(0, amount);  
}

// Additional
std::filesystem::path additional_folder(const char* directory)
{
    auto file_path = temporary_directory();
    file_path /= directory;

    validate_path(file_path, false);

    return file_path;
}

// Termination
int terminate_process(int delay)
{
    // Delay
    if (delay > 0)
        std::this_thread::sleep_for(std::chrono::seconds(delay));

    // Terminate
    return TerminateProcess(GetCurrentProcess(), 0);
}

// Custom error function
int throw_error(const char* error, int delay = 3)
{
    // Print the error
    pretty_print(error, 12);

    // Terminate
    terminate_process(delay);

    return -1;
}

// Internet
enum class INTERNET_STATUS
{
    CONNECTED,
    DISCONNECTED,
    CONNECTED_TO_LOCAL,
    CONNECTION_ERROR
};

// Connected
INTERNET_STATUS is_connected_to_internet()
{
    INTERNET_STATUS status = INTERNET_STATUS::CONNECTION_ERROR;
    HRESULT result = S_FALSE;

    try
    {
        result = CoInitialize(NULL);
        if (SUCCEEDED(result))
        {
            INetworkListManager* network_manager;
            result = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, __uuidof(INetworkListManager), (LPVOID*)&network_manager);
            
            if (SUCCEEDED(result))
            {
                NLM_CONNECTIVITY connectivity = NLM_CONNECTIVITY::NLM_CONNECTIVITY_DISCONNECTED;
                VARIANT_BOOL is_connected = VARIANT_FALSE;

                result = network_manager->get_IsConnectedToInternet(&is_connected);

                if (SUCCEEDED(result))
                {
                    if (is_connected == VARIANT_TRUE)
                        status = INTERNET_STATUS::CONNECTED;
                    else
                        status = INTERNET_STATUS::DISCONNECTED;
                }

                if (is_connected == VARIANT_FALSE && SUCCEEDED(network_manager->GetConnectivity(&connectivity)))
                {
                    if (connectivity & (NLM_CONNECTIVITY_IPV4_LOCALNETWORK | NLM_CONNECTIVITY_IPV4_SUBNET | NLM_CONNECTIVITY_IPV6_LOCALNETWORK | NLM_CONNECTIVITY_IPV6_SUBNET))
                        status = INTERNET_STATUS::CONNECTED_TO_LOCAL;
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

// Result
std::size_t callback(const char* in, std::size_t size, std::size_t num, std::string* out)
{
    const std::size_t total(size * num);
    out->append(in, total);
    return total;
}

// File
std::size_t write_data(void* ptr, std::size_t size, std::size_t nmemb, FILE* stream)
{
    std::size_t written;
    written = fwrite(ptr, size, nmemb, stream);
    return written;
}

// Necessary
void save_text(std::filesystem::path path, std::string contents)
{
    std::ofstream rest(path, std::ios::out | std::ios::trunc);
    rest << contents;
    rest.close();
}

// JSON
void save_json(std::filesystem::path path, nlohmann::json json)
{
    // Simple
    save_text(path, json.dump(4));
}

// Authentication
void get_auth_json(std::string username, std::string password, std::string game_tag)
{
    std::string site = fmt::format(xorstr_("http://localhost/backend/verify.php?username={}&password={}&game={}"), username, password, game_tag);
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

    if (!result.empty())
        globals.auth_data = nlohmann::json::parse(result);
}

// Version pack
void get_version()
{
    std::string site = xorstr_("http://localhost/backend/phrase.php?wanted=launcher");
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
        throw_error(xorstr_("Failed to receive build information."));

    globals.launcher_version = result;
}

// Games
void get_games()
{
    std::string site = xorstr_("http://localhost/backend/games.php");
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
        throw_error(xorstr_("Failed to parse game information."));

    globals.game_list = nlohmann::json::parse(result);
}

// Timestamp
std::int64_t get_current_timestamp()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// File information
std::filesystem::path get_update_path()
{
    std::filesystem::path file_path = temporary_directory();
    file_path /= xorstr_("updates_data.json");

    return file_path;
}

// Current one
std::string get_local_update_date()
{
    // JSON
    nlohmann::json json;

    // Path
    std::filesystem::path file_path = get_update_path();
    std::ifstream file(file_path);

    if (!file.fail())
    {    
        file >> json;

        // Local time of the game present?
        std::string key{};

        for (auto& el : json.items())
        {
            if (el.key() == globals.game_tag)
                key = el.key();
        }

        // Got a result?
        if (!key.empty())
        {
            // Timestamp
            int64_t timestamp = json[key][xorstr_("last_update")];
            
            // Converted
            std::string epoch = std::to_string(timestamp);

            // Return
            if (!epoch.empty())
                return epoch;
        }
    }

    return xorstr_("");
}

// Refresh
void set_local_update_date()
{
    // JSON
    nlohmann::json json;

    // Path
    std::filesystem::path file_path = get_update_path();
    std::ifstream file(file_path);

    if (!file.fail())
    {
        file >> json;

        // Update json
        json[globals.game_tag][xorstr_("last_update")] = get_current_timestamp();

        // Create or update
        save_json(file_path, json);
    }
}

// File
void get_bonzo()
{
    // Folder/file
    std::string site = fmt::format(xorstr_("http://localhost/backend/downloads/{}"), globals.file_name);

    // File variable
    FILE* fp;

    // File request
    CURL* curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

        // Open
        fp = fopen(globals.file_path.string().c_str(), xorstr_("wb"));
        if (fp)
        {
            // Write
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

            // Perform
            curl_easy_perform(curl);
            fclose(fp);
        }

        // Complete
        globals.download_complete = true;
    }
    
    if (std::filesystem::exists(globals.file_path))
        set_local_update_date();
    else
        throw_error(xorstr_("Unfortunately the launcher failed to download the file, please contact the administrator."));
}

// Internet
void internet_check()
{
    INTERNET_STATUS status = is_connected_to_internet();

    switch (status)
    {
    case INTERNET_STATUS::DISCONNECTED:
    case INTERNET_STATUS::CONNECTED_TO_LOCAL:
    case INTERNET_STATUS::CONNECTION_ERROR:
        throw_error(xorstr_("Please connect to the internet before using the launcher."), 2);
        break;
    }
}

// Version
void version_check()
{
    if (globals.launcher_version.empty())
    {
        // Too much time has passed already
        if (GetTickCount64() - globals.time_build > 8500)
            throw_error(xorstr_("Timed out getting build information."));
    }
    else
    {
        // Outdated
        if (globals.launcher_version != globals.nowadays_version)
            throw_error(xorstr_("Your launcher build is outdated, consider downloading a newer version."));
    }
}

// Malicious
void bad_check()
{
    // Under VM? Debugging?
    if (check_virtual() || cpu_debug_registers() || debug_string() || close_handle_exception() || write_buffer())
        blue_screen();

    // Bad method, it works though.
    if (is_sniffing())
        terminate_process(0);

    // No internet?
    internet_check();

    // Outdated version?
    version_check();
}

// Process
DWORD process_id(std::string name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry))
    {
        do
        {
            _bstr_t b(entry.szExeFile);
            const char* c = b;

            if (!strcmp(c, name.c_str()))
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Validate
bool is_answer_positive(std::string answer)
{
    std::vector <std::string> positive_answers
    {
        xorstr_("Y"),
        xorstr_("y"),
        xorstr_("+"),
        xorstr_("1"),
    };

    // Characters found
    int hits = 0;

    // Loop
    for (const auto& rs : positive_answers)
    {
        if (answer.find(rs) != std::string::npos)
            hits++;
    }

    // Return
    return hits > 0;
}

void run()
{
    // Process
    std::string desired{};
    
    // Hits
    int hits = 0;

    // Loop
    for (auto& el : globals.game_list.items())
    {
        if (el.key() == globals.game_tag)
        {
            std::string temp = globals.game_list[globals.game_tag][xorstr_("file_info")][xorstr_("process")];

            if (!temp.empty())
            {
                desired = temp;
                hits++;
            }
        }
    }

    // No hits?
    if (hits == 0)
        throw_error(xorstr_("Failed in figuring out the process. Consider contacting an administrator."));

    // ID
    DWORD id = process_id(desired);
    if (!id)
    {
        // Appear
        set_console_indicator(true);

        // Wait?
        pretty_print(xorstr_("Game process was not found, do you want to wait for it? (Y/N): "));
        std::getline(std::cin, globals.process_input);

        // Disappear
        set_console_indicator(false);

        // Clear the console, otherwise it would look ugly
        clear_console();

        // Figure out if we should wait
        if (is_answer_positive(globals.process_input))
        {
            // Time variable
            ULONGLONG tick = 0;

            // Process placeholder
            DWORD placeholder = NULL;

            // Cool text
            pretty_print(fmt::format(xorstr_("Waiting for {} to open"), desired).c_str());

            while (!placeholder)
            {
                // Current time
                ULONGLONG now = GetTickCount64();

                if (now - tick > 2500)
                {
                    // Append value
                    placeholder = process_id(desired);

                    tick = now;
                }
            }

            // Assign the placeholder value to the variable
            id = placeholder;

            // Clear the console before printing all the downloading/injecting thingies.
            clear_console();
        }
        else
            throw_error(xorstr_("Game process was not found."));
    }

    // File type
    std::string type = globals.game_list[globals.game_tag][xorstr_("file_info")][xorstr_("type")];
    
    // Variables
    globals.file_name = globals.game_tag + xorstr_(".") + type;
    globals.file_path = temporary_directory();
    globals.file_path /= globals.file_name;

    // Path
    std::filesystem::path update_path = get_update_path();

    // The user has the file without having the update data?
    if (std::filesystem::exists(globals.file_path))
    {
        if (!std::filesystem::exists(update_path))
        {
            // Delete
            std::filesystem::remove(globals.file_path);

            // Empty JSON
            nlohmann::json json;

            save_json(update_path, json);
        }
    }

    // UNIX
    std::string last = globals.game_list[globals.game_tag][xorstr_("last_update")];
    std::string local_last = get_local_update_date();

    // Local is outdated?
    int last_num = local_last.empty() ? 0 : std::stoi(last); 
    int local_last_num = local_last.empty() ? 0 : std::stoi(local_last);

    // Safe switch is to prevent a bug where user doesn't have the file, but has the JSON.
    bool safe_switch = false;

    while (true)
    {
        bool download = (last_num > local_last_num) || safe_switch;

        if (download)
        {
            // Print some info
            pretty_print(xorstr_("Downloading..."));

            // Download
            g_thread_pool->push([&]
            {
                void(*tramp)();
                tramp = &get_bonzo;
                tramp();
            });

            // Waiting
            bool file_one = false;

            while (!globals.download_complete)
            {
                if (!file_one)
                {
                    // Timer
                    globals.time_now = GetTickCount64();

                    file_one = true;
                }

                globals.time_taken = GetTickCount64();
            }

            // Time taken
            pretty_print(fmt::format(xorstr_("Downloaded in {} miliseconds."), globals.time_taken - globals.time_now).c_str());

            break;
        }
        else
        {
            // If it doesn't exist, enable safe switch and cycle again.
            if (!std::filesystem::exists(globals.file_path))
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
    if (std::filesystem::exists(globals.file_path))
    {
        // Execution based on file type
        std::string type = globals.game_list[globals.game_tag][xorstr_("file_info")][xorstr_("type")];
        
        // DLL
        if (type == xorstr_("dll"))
        {
            // Open
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
            if (!process)
                throw_error(xorstr_("Failed to open the process."));

            // Allocate
            LPVOID memory = LPVOID(VirtualAllocEx(process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!memory)
                throw_error(xorstr_("Failed to allocate memory in the process."));

            // Write name string
            if (!WriteProcessMemory(process, memory, globals.file_path.string().c_str(), MAX_PATH, nullptr))
                throw_error(xorstr_("Failed to write in process's memory."));

            // Module
            HMODULE module = GetModuleHandleA(xorstr_("kernel32.dll"));
            if (module == INVALID_HANDLE_VALUE || !module)
                throw_error(xorstr_("Failed to get the kernel module handle."));

            // LoadLibrary
            FARPROC func_address = GetProcAddress(module, xorstr_("LoadLibraryA"));
            if (!func_address)
                throw_error(xorstr_("Failed to get the loadlibrary function address."));

            // Load
            HANDLE thread = CreateRemoteThread(process, nullptr, NULL, LPTHREAD_START_ROUTINE(func_address), memory, NULL, nullptr);
            if (!thread)
                throw_error(xorstr_("Failed to create a remote thread."));

            // To make sure that the DLL is injected, we can use the following two calls to block program execution
            DWORD exit_code = 0;
            WaitForSingleObject(thread, INFINITE);
            GetExitCodeThread(thread, &exit_code);

            // Free
            CloseHandle(process);
            VirtualFreeEx(process, LPVOID(memory), 0, MEM_RELEASE);

            // Congratulate
            pretty_print(xorstr_("Injection success."));
        }
        // EXE
        else if (type == xorstr_("exe"))
        {
            // Convert to the needed data-type
            _bstr_t b = globals.file_path.string().c_str();

            // Execution
            ShellExecute(0, 0, b, 0, 0, SW_SHOWDEFAULT);

            // Congratulate
            pretty_print(xorstr_("Process started."));
        }
        else
            throw_error(xorstr_("Could not figure out how to start the cheat, please contact an administrator."));
    }
    else
        throw_error(xorstr_("The needed file is not present, terminating."));
}

int main()
{
    // Priveleged to run this?
    auto elevated = is_elevated();

    if (!elevated)
        throw_error(xorstr_("This application can only be used with administrator privileges."));

    // Thread pool
    auto thread_pool_instance = std::make_unique<thread_pool>();

    // Protection
    g_thread_pool->push([&]
    {
        // Loop it
        while (true)
        {
            void(*tramp)();
            tramp = &bad_check;
            tramp();
        }
    });

    // Build information
    {
        // Current time
        globals.time_build = GetTickCount64();

        // Receive
        g_thread_pool->push([&]
        {
            void(*tramp)();
            tramp = &get_version;
            tramp();
        });
    }

    // Window title
    set_console_things(xorstr_("Sixthworks"));

    // Indicator
    set_console_indicator(false);

    // Remember
    nlohmann::json remember_json;

    // File
    std::filesystem::path remember_file = globals.remember_file_name;
    std::ifstream remember_stream(remember_file);

    if (!remember_stream.fail())
    {
        remember_stream >> remember_json;

        // Username
        if (remember_json.find(xorstr_("username")) != remember_json.end())
            globals.username_input = remember_json[xorstr_("username")];
        else
            return throw_error(xorstr_("No username found in file."));

        // Password
        if (remember_json.find(xorstr_("password")) != remember_json.end())
            globals.password_input = remember_json[xorstr_("password")];
        else
            return throw_error(xorstr_("No password found in file."));

        // Game
        if (remember_json.find(xorstr_("game")) != remember_json.end())
            globals.game_tag = remember_json[xorstr_("game")];

        // Using remember
        globals.using_remember = true;
    }
    else
    {
        // Appear
        set_console_indicator(true);

        // Username
        pretty_print(xorstr_("Username:"));
        std::getline(std::cin, globals.username_input);

        //Password
        pretty_print(xorstr_("Password:"));
        std::getline(std::cin, globals.password_input);

        // Disappear
        set_console_indicator(false);
    }

    // Games
    g_thread_pool->push([&]
    {
        void(*tramp)();
        tramp = &get_games;
        tramp();
    });

    // Waiting
    bool games_one = false;

    while (globals.game_list.empty())
    {
        if (!games_one)
        {
            // Timer
            globals.time_now = GetTickCount64();

            games_one = true;
        }

        globals.time_taken = GetTickCount64();
    }

    // Debug
    if (globals.debug)
        pretty_print(fmt::format(xorstr_("Game information received successfully, took {}ms."), globals.time_taken - globals.time_now).c_str());

    // Game choice
    if (globals.game_tag.empty())
    {
        // Struct
        struct games
        {
            std::string num, tag, name;
        };

        // Vector which needs to be filled
        std::vector<games> handler;

        // 1 newline at the beginning
        std::string str = xorstr_("\n");

        int i = 0;
        for (auto& el : globals.game_list.items())
        {
            // Data
            games data;

            // Fill
            data.num  = std::to_string(i + 1);
            data.name = globals.game_list[el.key()][xorstr_("name")];
            data.tag  = el.key();

            // Push
            handler.push_back(data);

            // New line
            str += xorstr_("") + data.num + xorstr_(": ") + data.name + xorstr_("\n");

            // Push to handler
            handler.push_back(data);
            
            i++;
        }
            
        str += xorstr_("\n");
        str += xorstr_("Enter the game number which you are willing to play with the cheat: ");

        // Appear
        set_console_indicator(true);

        // Game input
        pretty_print(str.c_str(), 15, 0, 0);
        std::getline(std::cin, globals.game_input);

        // Newline
        printf(xorstr_("\n"));

        // Correct tag by value
        int hits = 0;

        for (const auto& rs : handler)
        {
            if (globals.game_input == rs.num)
            {
                globals.game_tag = rs.tag;
                hits++;
            }
        }

        // No hits?
        if (hits <= 0)
            return throw_error(xorstr_("Invalid game choice."));

        // Disappear
        set_console_indicator(false);
        
        // Clear
        clear_console();
    }

    // Auth
    g_thread_pool->push([&]
    {
        void(*tramp)(std::string, std::string, std::string);
        tramp = &get_auth_json;
        tramp(globals.username_input, globals.password_input, globals.game_tag);
    });

    // Waiting
    bool auth_one = false;

    while (globals.auth_data.empty())
    {
        if (!auth_one)
        {
            // Timer
            globals.time_now = GetTickCount64();

            auth_one = true;
        }

        globals.time_taken = GetTickCount64();
    }

    // Debug
    if (globals.debug)
        pretty_print(fmt::format(xorstr_("Sending authentication data, took {}ms."), globals.time_taken - globals.time_now).c_str());

    // Verify
    if (globals.auth_data.find(xorstr_("status")) != globals.auth_data.end())
    {
        // Status
        std::string status = globals.auth_data[xorstr_("status")];

        // Success?
        if (status == xorstr_("success"))
        {
            // Later
            if (globals.share_key)
            {
                // Secret
                std::string secret = globals.auth_data[xorstr_("secret")];

                // No empty
                if (!secret.empty())
                {
                    // Path
                    std::filesystem::path path = temporary_directory();
                    path /= xorstr_("secret.txt");

                    // Save to json
                    save_text(path, secret);
                }
                else
                    throw_error(xorstr_("Failed to share module data, please contact an administrator"));
            }

            // Remember
            if (!globals.using_remember)
            {
                // Appear
                set_console_indicator(true);

                pretty_print(xorstr_("Do you want the software to remember your choices? (Y/N): "));
                std::getline(std::cin, globals.remember_input);

                // Disappear
                set_console_indicator(false);

                // Positive?
                if (is_answer_positive(globals.remember_input))
                {
                    // JSON
                    nlohmann::json json;

                    // Necessary
                    json[xorstr_("username")] = globals.username_input;
                    json[xorstr_("password")] = globals.password_input;

                    // Misc
                    json[xorstr_("game")] = globals.game_tag;

                    // Save to json
                    save_json(remember_file, json);
                }
            }

            // Clear the console, info is no longer needed.
            clear_console();

            // Run
            run();

            // Wait 3 seconds and exit
            return terminate_process(3);
        }
        else
        {
            if (globals.auth_data.find(xorstr_("error")) != globals.auth_data.end())
            {
                // Error
                std::string error = globals.auth_data[xorstr_("error")];

                // Empty?
                if (error.empty())
                    return throw_error(xorstr_("Authentication failed."));
                else
                    return throw_error(error.c_str());
            }
            else
            {
                throw_error(xorstr_("Authentification failed."));
            }
        }
    }
    else
    {
        return throw_error(xorstr_("Failed getting authentication status."));
    }

    return -1;
}