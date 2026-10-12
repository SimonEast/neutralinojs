#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <filesystem>

#include "lib/json/json.hpp"
#include "settings.h"
#include "auth/permission.h"
#include "helpers.h"
#include "api/fs/fs.h"

using namespace std;
using json = nlohmann::json;

namespace permission {

vector<string> blockedMethods;
vector<string> blockedModules;
vector<string> allowedMethods;
vector<string> allowedModules;
vector<string> allowedCommandPatterns;
vector<string> fileSystemReadScopes;
vector<string> fileSystemWriteScopes;
bool shouldCheckBlockList = false;
bool shouldCheckAllowList = false;
bool shouldCheckCommandAllowList = false;
bool shouldCheckScopesLists = false;

bool __isWildcardMatch(const string &methodMatch) {
    return regex_match(methodMatch, regex(".*\\.\\*"));
}

string __getModuleFromMethod(const string &nativeMethod) {
    vector<string> methodParts = helpers::splitTwo(nativeMethod, '.');
    return methodParts[0];
}

string __normalizeScopePath(const string &path) {
    string resolved = fs::applyPathConstants(path);
    string norm = resolved;
    norm = FS_CONVWSTRN(filesystem::weakly_canonical(norm));
    norm = FS_CONVWSTRN(filesystem::absolute(norm));
    return helpers::normalizePath(norm);
}

bool __isPathInScope(const string &originalPath, const string &scope) {
    const string path = __normalizeScopePath(originalPath);
    if(path == scope) {
        return true;
    }
    if(path.size() > scope.size()
            && path.compare(0, scope.size(), scope) == 0
            && path[scope.size()] == '/') {
        return true;
    }
    return false;
}

void __registerBlockList() {
    blockedModules.clear();
    blockedMethods.clear();
    shouldCheckBlockList = false;

    json jNativeBlockList = settings::getOptionForCurrentMode("nativeBlockList");
    if(jNativeBlockList.is_null())
        return;
    vector<string> blockListVector = jNativeBlockList.get<vector<string>>();

    for(int i = 0; i < blockListVector.size(); i++) {
        // Adding blocked modules
        if(__isWildcardMatch(blockListVector[i])) {
            blockedModules.push_back(__getModuleFromMethod(blockListVector[i]));
        }
        // Adding blocked methods
        else {
            blockedMethods.push_back(blockListVector[i]);
        }
    }
    // Only activate blocklist enforcement if there are rules to block.
    // An empty blocklist ("nativeBlockList": []) blocks nothing and must NOT
    // deactivate nativeAllowList or alter authorization.
    if(!blockListVector.empty()) {
        shouldCheckBlockList = true;
    }
}

void __registerAllowList() {
    allowedModules.clear();
    allowedMethods.clear();
    shouldCheckAllowList = false;

    json jNativeAllowList = settings::getOptionForCurrentMode("nativeAllowList");
    if(jNativeAllowList.is_null())
        return;
    vector<string> allowListVector = jNativeAllowList.get<vector<string>>();

    for(int i = 0; i < allowListVector.size(); i++) {
        // Adding allowed modules
        if(__isWildcardMatch(allowListVector[i])) {
            allowedModules.push_back(__getModuleFromMethod(allowListVector[i]));
        }
        // Adding allowed methods
        else {
            allowedMethods.push_back(allowListVector[i]);
        }
    }
    shouldCheckAllowList = true;
}

void __regiserCommandAllowList() {
    json jCommandAllowList = settings::getOptionForCurrentMode("commandAllowList");
    if(jCommandAllowList.is_null())
        return;
    allowedCommandPatterns = jCommandAllowList.get<vector<string>>();
    shouldCheckCommandAllowList = true;
}

void __registerScopesLists() {
    json jScopes = settings::getOptionForCurrentMode("filesystemScopes");
    if(jScopes.is_null())
        return;

    for(const auto &entry: jScopes.items()) {
        string perm = entry.value().get<string>();
        string normalizedScope = __normalizeScopePath(entry.key());
        if(perm == "read-write" || perm == "read") {
            fileSystemReadScopes.push_back(normalizedScope);
        }
        if(perm == "read-write" || perm == "write") {
            fileSystemWriteScopes.push_back(normalizedScope);
        }
    }

    shouldCheckScopesLists = true;
}

// Security fix for GHSA-7h48-j4q4-qwf3 (CWE-284 / CWE-863: Incorrect Authorization)
//
// Threat Model:
// Neutralino supports two native API access lists: nativeAllowList and nativeBlockList.
// Previously, if nativeBlockList was present in config (even as an empty array []),
// the check returned true for any unblocked method without evaluating nativeAllowList.
// This meant setting a blocklist inadvertently bypassed and disabled the allowlist,
// exposing sensitive unlisted native APIs (filesystem, os, computer, storage) to JavaScript.
//
// Policy (Defense-in-Depth & Principle of Least Privilege):
// 1. Blocklist check (negative constraint): If nativeBlockList is active, any method matching
//    a blocked module or blocked method is immediately denied.
// 2. Allowlist check (positive boundary): If nativeAllowList is active, only methods explicitly
//    matching an allowed module or allowed method are permitted. Any unlisted method is denied.
// 3. When both lists are defined, the intersection is enforced: the method must be allowed
//    by nativeAllowList AND not blocked by nativeBlockList.
// 4. Default: If neither list is configured, all methods are permitted by default.
bool hasMethodAccess(const string &nativeMethod) {
    string module = __getModuleFromMethod(nativeMethod);

    // 1. Check negative constraint (blocklist). If blocked, deny immediately.
    if(shouldCheckBlockList) {
        if(find(blockedModules.begin(), blockedModules.end(), module)
                != blockedModules.end()) {
            return false;
        }

        if(find(blockedMethods.begin(), blockedMethods.end(), nativeMethod)
                != blockedMethods.end()) {
            return false;
        }
    }

    // 2. Check positive constraint (allowlist). If an allowlist is configured,
    // only listed methods/modules are allowed.
    if(shouldCheckAllowList) {
        if(find(allowedModules.begin(), allowedModules.end(), module)
                != allowedModules.end()) {
            return true;
        }

        if(find(allowedMethods.begin(), allowedMethods.end(), nativeMethod)
                != allowedMethods.end()) {
            return true;
        }
        return false; // Method is not in allowlist -> denied
    }

    // 3. If no allowlist is configured and the method was not blocked, permit access.
    return true;
}

bool hasAPIAccess() {
    json jEnableNativeAPI = settings::getOptionForCurrentMode("enableNativeAPI");
    if(!jEnableNativeAPI.is_null())
        return jEnableNativeAPI.get<bool>();
    return false;
}

bool hasCommandExecutionAccess(const string &command) {
    if(!shouldCheckCommandAllowList || allowedCommandPatterns.empty()) {
        return true;
    }

    vector<string> tokens = helpers::tokenizeCommand(command);
    if(tokens.empty()) {
        return false;
    }

    string program = tokens[0];
    for(const string &pattern: allowedCommandPatterns) {
        if(helpers::globalMatch(program, pattern)) {
            return true;
        }
    }
    return false;
}


bool hasFileSystemPathAccess(const string &path, permission::FileSystemAccessPermission perm) {
    if(!shouldCheckScopesLists) {
        return true;
    }

    const auto activeScopes = (perm == permission::FileSystemAccessPermissionWrite)
        ? fileSystemWriteScopes : fileSystemReadScopes;

    if(activeScopes.empty()) {
        return false;
    }

    for(const string &scope: activeScopes) {
        if(__isPathInScope(path, scope)) {
            return true;
        }
    }
    return false;
}

void init() {
    __registerAllowList();
    __registerBlockList();
    __regiserCommandAllowList();
    __registerScopesLists();
}

} // namespace permission
