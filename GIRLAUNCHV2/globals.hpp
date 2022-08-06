#pragma once
#include "xorstr.hpp"

struct globals_s
{
public:
	// Debug mode
	bool debug{ false };

	// Necessary
	bool save_details_for_work{ true };
	bool verify_launcher_version{ true };

	// Remember
	bool using_remember;
	std::string remember_file_name = xorstr_("remember.json");

	// JSON
	nlohmann::json crc_data;
	nlohmann::json auth_data;
	nlohmann::json game_list;

	// Game
	std::string game_tag;

	// Inputs
	std::string username_input;
	std::string password_input;
	std::string remember_input;
	std::string process_input;
	std::string game_input;

	// Download
	std::string file_name;
	std::filesystem::path file_path;

	// Debug
	ULONGLONG time_taken;
	ULONGLONG time_now;
};

inline struct globals_s globals;