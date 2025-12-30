#pragma once
#include <string>
#include <map>

class Config {
public:
    Config();
    bool load(const std::string& filename);
    std::string getString(const std::string& section, const std::string& name, const std::string& def = "") const;
    int getInt(const std::string& section, const std::string& name, int def = 0) const;
    bool getBool(const std::string& section, const std::string& name, bool def = false) const;
private:
    std::map<std::string, std::map<std::string, std::string>> _data;
    std::string trim(const std::string& s) const;
};
