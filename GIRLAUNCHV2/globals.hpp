#pragma once
#include "xorstr.hpp"

struct globals_s
{
public:
	// Debug mode
	bool debug{ false };

	// Necessary
	bool share_key{ true };

	// Version
	std::string launcher_version;
	std::string nowadays_version{ xorstr_("FullMonster") };

	// Remember
	bool using_remember;

	std::string remember_file_name{ xorstr_("remember_me.json") };

	// JSON
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
	bool download_complete{ false };
	std::filesystem::path file_path;

	// Time
	ULONGLONG time_taken;
	ULONGLONG time_build;
	ULONGLONG time_now;
};

inline struct globals_s globals;