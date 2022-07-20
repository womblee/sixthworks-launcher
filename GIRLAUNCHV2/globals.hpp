#pragma once
#include "xorstr.hpp"

struct globals_s
{
public:
	bool save_details_for_work{ true };
	bool verify_launcher_version{ true };

	bool using_remember;
	std::string remember_file_name = xorstr_("remember.json");
	
	std::string current_version = xorstr_("0.0.1");
	std::string parsed_version;

	nlohmann::json auth_data;
	nlohmann::json game_list;

	std::string game_tag;

	std::string username_input;
	std::string password_input;
	std::string remember_input;
	std::string process_input;
	std::string game_input;

	std::string file_name;
	std::filesystem::path file_path;

	ULONGLONG time_taken;
	ULONGLONG time_now;
};

inline struct globals_s globals;