#ifndef CONFIG_MGR_H
#define CONFIG_MGR_H

#include <Arduino.h>
#include <Preferences.h>
#include <vector>

struct AppConfig {
    bool blockingEnabled = true;
    String upstreamDns1 = "94.140.14.14"; // AdGuard DNS (Ad & Tracker Blocking)
    String upstreamDns2 = "94.140.15.15"; // AdGuard DNS Secondary (Failover)
    
    // IP mode: true = Static (192.168.1.95), false = DHCP
    bool useStaticIp = true;
    String staticIp = "107.7.97.95";
    String staticGateway = "107.7.97.77";
    String staticSubnet = "255.255.255.0";
    String staticDns = "1.1.1.1";
};

class ConfigManager {
private:
    Preferences prefs;
    AppConfig config;
    std::vector<String> customWhitelist;
    std::vector<String> customBlacklist;

public:
    void begin() {
        prefs.begin("adblocker", false);
        config.blockingEnabled = prefs.getBool("blk_en", true);
        config.upstreamDns1 = prefs.getString("dns1", "1.1.1.1");
        config.upstreamDns2 = prefs.getString("dns2", "8.8.8.8");
        config.useStaticIp = prefs.getBool("static_en", true);
        config.staticIp = prefs.getString("ip", "192.168.1.95");
        config.staticGateway = prefs.getString("gw", "192.168.1.1");
        config.staticSubnet = prefs.getString("sub", "255.255.255.0");
        config.staticDns = prefs.getString("sdns", "1.1.1.1");
        
        loadLists();
    }

    AppConfig& getConfig() {
        return config;
    }

    void saveConfig() {
        prefs.putBool("blk_en", config.blockingEnabled);
        prefs.putString("dns1", config.upstreamDns1);
        prefs.putString("dns2", config.upstreamDns2);
        prefs.putBool("static_en", config.useStaticIp);
        prefs.putString("ip", config.staticIp);
        prefs.putString("gw", config.staticGateway);
        prefs.putString("sub", config.staticSubnet);
        prefs.putString("sdns", config.staticDns);
    }

    void parseCommaSeparated(const String& str, std::vector<String>& list) {
        if (str.length() == 0) return;
        int start = 0;
        int idx = str.indexOf(',');
        while (idx != -1) {
            String d = cleanDomain(str.substring(start, idx));
            if (d.length() > 0) {
                bool exists = false;
                for (const auto& item : list) {
                    if (item == d) { exists = true; break; }
                }
                if (!exists) list.push_back(d);
            }
            start = idx + 1;
            idx = str.indexOf(',', start);
        }
        String last = cleanDomain(str.substring(start));
        if (last.length() > 0) {
            bool exists = false;
            for (const auto& item : list) {
                if (item == last) { exists = true; break; }
            }
            if (!exists) list.push_back(last);
        }
    }

    void loadLists() {
        customWhitelist.clear();
        customBlacklist.clear();
        
        // 1. Whitelist: Check chunked keys first
        int wlChunks = prefs.getInt("wl_c", -1);
        if (wlChunks > 0) {
            for (int c = 0; c < wlChunks; c++) {
                parseCommaSeparated(prefs.getString(("w_" + String(c)).c_str(), ""), customWhitelist);
            }
        } else {
            // Legacy single "wl" key fallback
            parseCommaSeparated(prefs.getString("wl", ""), customWhitelist);
        }

        // 2. Blacklist: Check chunked keys first
        int blChunks = prefs.getInt("bl_c", -1);
        if (blChunks > 0) {
            for (int c = 0; c < blChunks; c++) {
                parseCommaSeparated(prefs.getString(("b_" + String(c)).c_str(), ""), customBlacklist);
            }
        } else {
            // Legacy single "bl" key fallback
            parseCommaSeparated(prefs.getString("bl", ""), customBlacklist);
        }
    }

    void saveLists() {
        const size_t CHUNK_SIZE = 30; // 30 domains per chunk (~500 bytes, safely below 1984/4000 byte NVS limits)

        // Save Whitelist
        int oldWlChunks = prefs.getInt("wl_c", 0);
        int wlChunks = 0;
        if (!customWhitelist.empty()) {
            wlChunks = (customWhitelist.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
            for (int c = 0; c < wlChunks; c++) {
                String chunkStr = "";
                size_t start = c * CHUNK_SIZE;
                size_t end = std::min(customWhitelist.size(), start + CHUNK_SIZE);
                for (size_t i = start; i < end; i++) {
                    if (i > start) chunkStr += ",";
                    chunkStr += customWhitelist[i];
                }
                prefs.putString(("w_" + String(c)).c_str(), chunkStr);
            }
        }
        for (int c = wlChunks; c < oldWlChunks + 5; c++) {
            prefs.remove(("w_" + String(c)).c_str());
        }
        prefs.putInt("wl_c", wlChunks);
        prefs.remove("wl"); // Clear legacy key

        // Save Blacklist
        int oldBlChunks = prefs.getInt("bl_c", 0);
        int blChunks = 0;
        if (!customBlacklist.empty()) {
            blChunks = (customBlacklist.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
            for (int c = 0; c < blChunks; c++) {
                String chunkStr = "";
                size_t start = c * CHUNK_SIZE;
                size_t end = std::min(customBlacklist.size(), start + CHUNK_SIZE);
                for (size_t i = start; i < end; i++) {
                    if (i > start) chunkStr += ",";
                    chunkStr += customBlacklist[i];
                }
                prefs.putString(("b_" + String(c)).c_str(), chunkStr);
            }
        }
        for (int c = blChunks; c < oldBlChunks + 10; c++) {
            prefs.remove(("b_" + String(c)).c_str());
        }
        prefs.putInt("bl_c", blChunks);
        prefs.remove("bl"); // Clear legacy key
    }

    static String cleanDomain(const String& d) {
        String s = d;
        s.trim();
        s.toLowerCase();
        if (s.startsWith("http://")) s = s.substring(7);
        if (s.startsWith("https://")) s = s.substring(8);
        int slash = s.indexOf('/');
        if (slash != -1) s = s.substring(0, slash);
        int colon = s.indexOf(':');
        if (colon != -1) s = s.substring(0, colon);
        if (s.startsWith("www.")) s = s.substring(4);
        return s;
    }

    bool isCustomWhitelisted(const String& domain) {
        String lower = domain;
        lower.toLowerCase();
        String clean = cleanDomain(lower);
        for (const auto& item : customWhitelist) {
            String itemClean = cleanDomain(item);
            if (lower == item || lower.endsWith("." + item) ||
                clean == itemClean || clean.endsWith("." + itemClean) ||
                lower.endsWith("." + itemClean)) {
                return true;
            }
        }
        return false;
    }

    bool isCustomBlacklisted(const String& domain) {
        String lower = domain;
        lower.toLowerCase();
        String clean = cleanDomain(lower);
        for (const auto& item : customBlacklist) {
            String itemClean = cleanDomain(item);
            if (lower == item || lower.endsWith("." + item) ||
                clean == itemClean || clean.endsWith("." + itemClean) ||
                lower.endsWith("." + itemClean)) {
                return true;
            }
        }
        return false;
    }

    bool addWhitelist(const String& domain) {
        String d = cleanDomain(domain);
        if (d.length() == 0) return false;
        for (const auto& item : customWhitelist) {
            if (cleanDomain(item) == d) return false;
        }
        customWhitelist.push_back(d);
        saveLists();
        return true;
    }

    bool removeWhitelist(const String& domain) {
        String d = cleanDomain(domain);
        for (auto it = customWhitelist.begin(); it != customWhitelist.end(); ++it) {
            if (cleanDomain(*it) == d) {
                customWhitelist.erase(it);
                saveLists();
                return true;
            }
        }
        return false;
    }

    bool addBlacklist(const String& domain) {
        String d = cleanDomain(domain);
        if (d.length() == 0) return false;
        for (const auto& item : customBlacklist) {
            if (cleanDomain(item) == d) return false;
        }
        customBlacklist.push_back(d);
        saveLists();
        return true;
    }

    bool removeBlacklist(const String& domain) {
        String d = cleanDomain(domain);
        for (auto it = customBlacklist.begin(); it != customBlacklist.end(); ++it) {
            if (cleanDomain(*it) == d) {
                customBlacklist.erase(it);
                saveLists();
                return true;
            }
        }
        return false;
    }

    size_t addBulk(const std::vector<String>& domains, bool isWhitelist) {
        size_t added = 0;
        auto& list = isWhitelist ? customWhitelist : customBlacklist;
        for (String d : domains) {
            String clean = cleanDomain(d);
            if (clean.length() == 0) continue;
            bool exists = false;
            for (const auto& item : list) {
                if (cleanDomain(item) == clean) { exists = true; break; }
            }
            if (!exists) {
                list.push_back(clean);
                added++;
            }
        }
        if (added > 0) {
            saveLists();
        }
        return added;
    }

    void clearList(bool isWhitelist) {
        if (isWhitelist) customWhitelist.clear();
        else customBlacklist.clear();
        saveLists();
    }

    const std::vector<String>& getWhitelist() const { return customWhitelist; }
    const std::vector<String>& getBlacklist() const { return customBlacklist; }
};

extern ConfigManager configMgr;

#endif // CONFIG_MGR_H
