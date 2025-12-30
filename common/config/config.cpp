#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

Config::Config() {}

bool Config::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::string line, currentSection;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';') continue;
        if (line[0] == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = trim(line.substr(0, eqPos));
            std::string value = trim(line.substr(eqPos + 1));
            _data[currentSection][key] = value;
        }
    }
    return true;
}

std::string Config::getString(const std::string& section, const std::string& name, const std::string& def) const {
    auto secIt = _data.find(section);
    if (secIt != _data.end()) {
        auto valIt = secIt->second.find(name);
        if (valIt != secIt->second.end()) return valIt->second;
    }
    return def;
}

int Config::getInt(const std::string& section, const std::string& name, int def) const {
    std::string val = getString(section, name, "");
    if (val.empty()) return def;
    try {
        return std::stoi(val);
    } catch (...) {
        return def;
    }
}

bool Config::getBool(const std::string& section, const std::string& name, bool def) const {
    std::string val = getString(section, name, "");
    if (val.empty()) return def;
    std::transform(val.begin(), val.end(), val.begin(), ::tolower);
    if (val == "true" || val == "1" || val == "yes" || val == "on") return true;
    if (val == "false" || val == "0" || val == "no" || val == "off") return false;
    return def;
}

std::string Config::trim(const std::string& s) const {
    size_t start = s.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t");
    return s.substr(start, end - start + 1);
}
