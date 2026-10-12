#include <string>
#include <regex>
#include <map>
#include <thread>
#include <chrono>
#include <set>
#include <fstream>
#include <algorithm>

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include "lib/json/json.hpp"
#include "settings.h"
#include "helpers.h"
#include "errors.h"
#include "extensions_loader.h"
#include "server/neuserver.h"
#include "server/router.h"
#include "auth/authbasic.h"
#include "api/debug/debug.h"
#include "api/events/events.h"
#include "api/app/app.h"
#include "api/fs/fs.h"


using namespace std;
using json = nlohmann::json;

typedef websocketpp::server<websocketpp::config::asio> websocketserver;
typedef map<string, websocketpp::connection_hdl> wsclientsMap;
typedef set<websocketpp::connection_hdl, owner_less<websocketpp::connection_hdl>> wsclientsSet;

namespace neuserver {

websocketserver *server;
wsclientsSet appConnections;
wsclientsMap extConnections;
map<websocketpp::connection_hdl,
    websocketpp::frame::opcode::value,
    owner_less<websocketpp::connection_hdl>> wsMode;

string serverHost = "127.0.0.1";
bool initialized = false;
bool applyConfigHeaders = false;

bool __isExtensionEndpoint(const string &url) {
    return regex_match(url, regex(".*extensionId=.*"));
}

bool __hasConnectToken(const string &url) {
    return regex_match(url, regex(".*connectToken=.*"));
}

fs::FileReaderOptions __getFileReaderOptionsFromHeaders(const websocketpp::http::parser::header_list &headers) {
    fs::FileReaderOptions fileReaderOptions;
    auto rangeIt = headers.find("Range");
    if(rangeIt == headers.end()) {
        return fileReaderOptions;
    }

    smatch match;
    if(regex_match(rangeIt->second, match, regex(R"(bytes=(\d+)-(\d*)?)"))) {
        fileReaderOptions.pos = stoll(match[1].str());
        if(match[2].matched && match[2].str() != "") {
            long long end = stoll(match[2].str());
            if(end >= fileReaderOptions.pos) {
                fileReaderOptions.size = end - fileReaderOptions.pos + 1;
            }
        }
    }
    return fileReaderOptions;
}

void __applyConfigHeaders(websocketserver::connection_ptr con) {
    json jHeaders = settings::getOptionForCurrentMode("serverHeaders");
    for(const auto &it: jHeaders.items()) {
        con->replace_header(it.key(), it.value().get<string>());
    }
}

string __getParamValueFromUrl(const string &url, const string &param) {
    string val = "";
    smatch matches;
    if(regex_search(url, matches, regex(param + "=([\\w.\\-_]+)"))) {
        if(matches.size() >= 2) {
            val = matches[1].str();
        }
    }
    return val;
}

string __getExtensionIdFromUrl(const string &url) {
    return __getParamValueFromUrl(url, "extensionId");
}

string __getConnectTokenFromUrl(const string &url) {
    return __getParamValueFromUrl(url, "connectToken");
}

void __exitProcessIfIdle() {
    thread exitCheckThread([=]() {
        this_thread::sleep_for(10s);
        if(appConnections.size() == 0) {
            app::exit();
        }
    });
    exitCheckThread.detach();
}

// Helper function to extract hostname from an Origin header or URL
// per RFC 6454 (e.g., "http://localhost:8080" -> "localhost", "https://[::1]:3000" -> "::1")
string __extractHostFromOrigin(const string &origin) {
    if(origin.empty() || origin == "null") {
        return "";
    }
    size_t schemePos = origin.find("://");
    if(schemePos == string::npos) {
        return "";
    }
    string authority = origin.substr(schemePos + 3);

    // Strip trailing path, query, or fragment if present
    size_t endPos = authority.find_first_of("/?#");
    if(endPos != string::npos) {
        authority = authority.substr(0, endPos);
    }

    string host;
    if(!authority.empty() && authority.front() == '[') {
        // IPv6 bracketed address literal, e.g. [::1]:8080
        size_t closeBracket = authority.find(']');
        if(closeBracket == string::npos) {
            return "";
        }
        host = authority.substr(1, closeBracket - 1);
    } else {
        size_t colonPos = authority.find(':');
        if(colonPos != string::npos) {
            host = authority.substr(0, colonPos);
        } else {
            host = authority;
        }
    }

    transform(host.begin(), host.end(), host.begin(), ::tolower);
    return host;
}

// Security fix for GHSA-rjgv-ffxc-h5c2 (CWE-346: Origin Validation Error)
//
// Threat Model:
// Cross-Site WebSocket Hijacking (CSWSH). In desktop modes (window, browser, chrome),
// the WebSocket connection should only be initiated by the application frontend running
// locally (or from a developer-configured external URL/dev server).
// Browsers always send the destination host in the HTTP "Host" header, so checking "Host"
// alone provides zero protection against malicious external websites (e.g. https://evil.example)
// attempting to establish a WebSocket connection to ws://127.0.0.1:<port> if they obtain or
// leak the connect token.
// The browser's "Origin" header cannot be forged or overridden by client-side JavaScript.
//
// Policy:
// 1. Cloud mode: Per CHANGELOG v5.0.0, any origin is permitted in cloud mode.
// 2. Empty Origin: Non-browser clients (native extensions, internal helper processes,
//    CLI tools) do not send an Origin header and are allowed per RFC 6455 §4.2.1.
// 3. "null" Origin: Untrusted opaque origin (sandboxed iframe / data: URI) is rejected.
// 4. Desktop modes: The origin host must match:
//    - Loopback addresses: "localhost", "127.0.0.1", or "::1".
//    - The configured serverHost (if explicitly bound via --host / config).
//    - If serverHost is "0.0.0.0", the requesting IP address matching reqHost.
//    - The host of any configured "url" option (e.g., remote URL or dev server).
bool __isOriginAllowed(const string &origin, const string &reqHost) {
    // 1. Cloud mode allows any origin
    if(settings::getMode() == settings::AppModeCloud) {
        return true;
    }

    // 2. Non-browser clients (extensions, background daemons, curl) do not set Origin
    if(origin.empty()) {
        return true;
    }

    // 3. Reject opaque "null" origins
    if(origin == "null") {
        return false;
    }

    // 4. Extract host from origin
    string originHost = __extractHostFromOrigin(origin);
    if(originHost.empty()) {
        return false;
    }

    // 5. Allow standard loopback origins
    if(originHost == "localhost" || originHost == "127.0.0.1" || originHost == "::1") {
        return true;
    }

    // 6. Allow explicitly configured serverHost (e.g. --host=192.168.1.100)
    if(!serverHost.empty() && serverHost != "0.0.0.0" && originHost == serverHost) {
        return true;
    }

    // 7. If serverHost is 0.0.0.0 (all interfaces), allow if originHost matches request host
    //    and is a valid IP address (preventing DNS rebinding)
    if(serverHost == "0.0.0.0" && originHost == reqHost) {
        websocketpp::lib::asio::error_code ec;
        websocketpp::lib::asio::ip::address::from_string(originHost, ec);
        if(!ec) {
            return true;
        }
    }

    // 8. Allow if origin matches configured "url" option (e.g. Vite dev server, remote web app)
    json jUrl = settings::getOptionForCurrentMode("url");
    if(!jUrl.is_null()) {
        string configUrl = jUrl.get<string>();
        string configHost = __extractHostFromOrigin(configUrl);
        if(!configHost.empty() && originHost == configHost) {
            return true;
        }
    }

    return false;
}

string init() {
    int port = 0;
    json jPort = settings::getOptionForCurrentMode("port");
    if(!jPort.is_null()) {
        port = jPort.get<int>();
    }
    server = new websocketserver();

    server->set_message_handler([&](websocketpp::connection_hdl handler, websocketserver::message_ptr msg) {
        neuserver::handleMessage(handler, msg);
    });

    server->set_http_handler([&](websocketpp::connection_hdl handler) {
        neuserver::handleHTTP(handler);
    });

    server->set_open_handler([&](websocketpp::connection_hdl handler) {
        neuserver::handleConnect(handler);
    });

    server->set_close_handler([&](websocketpp::connection_hdl handler) {
        neuserver::handleDisconnect(handler);
    });

    server->set_validate_handler([&](websocketpp::connection_hdl handler) {
        return neuserver::handleValidate(handler);
    });

    server->set_access_channels(websocketpp::log::alevel::none);
    server->set_error_channels(websocketpp::log::elevel::none);

    server->init_asio();
    server->set_reuse_addr(true);

    // Security fix for GHSA-fp96-mrqq-p5rq (CWE-1327): Binding to an Unrestricted IP Address
    //
    // Threat Model:
    // In cloud mode, Neutralino acts as a headless server, defaulting to listening on all interfaces
    // (0.0.0.0) so external devices (mobile phones, IoT, Docker hosts) can connect. However,
    // because static HTTP file serving does not require a WebSocket token, listening on 0.0.0.0
    // exposes the app's local assets and endpoints to any device on the network without any warning.
    //
    // Defense:
    // 1. Maintain 127.0.0.1 (loopback) default for desktop modes (window, browser, chrome).
    // 2. Allow developers to explicitly configure the bind interface via "host" in config or "--host" CLI option
    //    (e.g. allowing developers to restrict cloud mode to 127.0.0.1 for local container/daemon isolation).
    // 3. When binding to an external/unrestricted interface (0.0.0.0 or non-loopback), emit a bold security
    //    warning recommending caution and informing developers how to restrict it.
    string hostAddress = (settings::getMode() == settings::AppModeCloud) ? "0.0.0.0" : "127.0.0.1";
    json jHost = settings::getOptionForCurrentMode("host");
    if(!jHost.is_null() && !jHost.get<string>().empty()) {
        hostAddress = jHost.get<string>();
    }

    websocketpp::lib::asio::error_code addrError;
    auto ipAddress = websocketpp::lib::asio::ip::address::from_string(hostAddress, addrError);
    if(addrError) {
        debug::log(debug::LogTypeError, "Invalid host address '" + hostAddress + "'; falling back to 127.0.0.1");
        hostAddress = "127.0.0.1";
        ipAddress = websocketpp::lib::asio::ip::address::from_string("127.0.0.1");
    }

    if(hostAddress != "127.0.0.1" && hostAddress != "localhost" && hostAddress != "::1") {
        debug::log(debug::LogTypeWarning, "SECURITY WARNING: Server is listening on an external network interface (" + hostAddress +
            "). Static files and server endpoints are accessible to other devices on the network. Configure firewall rules or use '--host=127.0.0.1' for local isolation.");
    }
    serverHost = hostAddress;

    websocketpp::lib::asio::ip::tcp::endpoint endpoint(ipAddress, port);

    server->listen(endpoint);
    server->start_accept();

    websocketpp::lib::asio::error_code error;
    int actualPort = server->get_local_endpoint(error).port();

    if(port != actualPort) {
        port = actualPort;
        settings::setPort(port);
    }

    string navigationUrl = "http://127.0.0.1:" + to_string(port);
    json jUrl = settings::getOptionForCurrentMode("url");

    if(!jUrl.is_null()) {
        string url = jUrl.get<string>();
        if (regex_match(url, regex("^/.*")))
            navigationUrl += url;
        else
            navigationUrl = url;
    }
    initialized = true;

    json jHeaders = settings::getOptionForCurrentMode("serverHeaders");
    if(!jHeaders.is_null()) {
        applyConfigHeaders = true;
    }

    return navigationUrl;
}

bool isInitialized() {
    return initialized;
}

void startAsync() {
    thread serverThread([&](){ server->run(); });
    serverThread.detach();
}

void stop() {
    server->stop_listening();
}

void handleMessage(websocketpp::connection_hdl handler, websocketserver::message_ptr msg) {
    websocketserver::connection_ptr con = server->get_con_from_hdl(handler);
    string url = con->get_resource();
    if(__isExtensionEndpoint(url) && wsMode.find(handler) == wsMode.end()) {
        if(msg->get_opcode() == websocketpp::frame::opcode::text) {
        	wsMode[handler] = websocketpp::frame::opcode::text;
        }
        else if(msg->get_opcode() == websocketpp::frame::opcode::binary) {
        	wsMode[handler] = websocketpp::frame::opcode::binary;
        }
    }
    json nativeMessage;
    try {
        nativeMessage = json::parse(msg->get_payload());
        router::NativeMessage nativeResponse = router::executeNativeMethod({
            nativeMessage["id"].get<string>(),
            nativeMessage["method"].get<string>(),
            nativeMessage["accessToken"].get<string>(),
            nativeMessage["data"]
        });

        try {
            json responseMessage;
            responseMessage["id"] = nativeResponse.id;
            responseMessage["method"] = nativeResponse.method;
            responseMessage["data"] = nativeResponse.data;

            auto op = websocketpp::frame::opcode::text;

            if(__isExtensionEndpoint(url) && wsMode.count(handler)) {
                op = wsMode[handler];
            }

            server->send(handler, helpers::jsonToString(responseMessage), op);
        } catch (websocketpp::exception const & e) {
            debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_SR_UNBSEND));
        }
    }
    catch(const exception& e) {
        debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_SR_UNBPARS));
    }
}

void handleHTTP(websocketpp::connection_hdl handler) {
    websocketserver::connection_ptr con = server->get_con_from_hdl(handler);
    string resource = con->get_resource();
    string documentRoot = neuserver::getDocumentRoot();
    if(!documentRoot.empty()) {
        resource = documentRoot + resource;
    }
    fs::FileReaderOptions fileReaderOptions =
        __getFileReaderOptionsFromHeaders(con->get_request().get_headers());
    router::Response routerResponse = router::serve(resource, fileReaderOptions);
    con->set_status(routerResponse.status);
    con->set_body(routerResponse.data);
    con->replace_header("Content-Type",routerResponse.contentType);
    for(const auto &[header, value]: routerResponse.headers) {
        con->replace_header(header, value);
    }
    
    if(applyConfigHeaders){
        __applyConfigHeaders(con);
    }
}

void handleConnect(websocketpp::connection_hdl handler) {
    websocketserver::connection_ptr con = server->get_con_from_hdl(handler);
    string url = con->get_resource();
    if(__isExtensionEndpoint(url)) {
        string extensionId = __getExtensionIdFromUrl(url);
        extConnections[extensionId] = handler;
        events::dispatch("extClientConnect", extensionId);
    }
    else {
        appConnections.insert(handler);
        events::dispatch("appClientConnect", appConnections.size());
    }
    events::dispatch("clientConnect", appConnections.size() + extConnections.size());
}

void handleDisconnect(websocketpp::connection_hdl handler) {
    wsMode.erase(handler);
    
    websocketserver::connection_ptr con = server->get_con_from_hdl(handler);
    string url = con->get_resource();
    if(__isExtensionEndpoint(url)) {
        string extensionId = __getExtensionIdFromUrl(url);
        extConnections.erase(extensionId);
        events::dispatch("extClientDisconnect", extensionId);
    }
    else {
        settings::AppMode mode = settings::getMode();
        appConnections.erase(handler);
        if(mode == settings::AppModeBrowser || mode == settings::AppModeChrome) {
            __exitProcessIfIdle();
        }
        events::dispatch("appClientDisconnect", appConnections.size());
    }
    events::dispatch("clientDisconnect", appConnections.size() + extConnections.size());
}

bool handleValidate(websocketpp::connection_hdl handler) {
    websocketserver::connection_ptr con = server->get_con_from_hdl(handler);
    string url = con->get_resource();
    string host = con->get_host();

    if(!(host == "localhost" || host == "127.0.0.1" || host == serverHost || serverHost == "0.0.0.0") && settings::getMode() != settings::AppModeCloud) {
        return false;
    }

    // Security fix for GHSA-rjgv-ffxc-h5c2 (CWE-346: Origin Validation Error)
    // Enforce Origin validation during WebSocket handshake to prevent Cross-Site WebSocket Hijacking (CSWSH)
    string origin = con->get_request_header("Origin");
    if(!__isOriginAllowed(origin, host)) {
        con->set_status(websocketpp::http::status_code::forbidden);
        return false;
    }

    if(!__hasConnectToken(url)) {
        return false;
    }

    string connectToken = __getConnectTokenFromUrl(url);
    if(!authbasic::verifyConnectToken(connectToken)) {
        return false;
    }

    if(__isExtensionEndpoint(url)) {
        string extensionId = __getExtensionIdFromUrl(url);
        return extensions::isLoaded(extensionId);
    }

    return true;
}

void broadcast(const json &message) {
    neuserver::broadcastToAllApps(message);
    neuserver::broadcastToAllExtensions(message); 
}

bool sendToExtension(const string &extensionId, const json &message) {
    if(extConnections.find(extensionId) != extConnections.end()) {
        auto hdl = extConnections[extensionId];
        auto op = wsMode.count(hdl)
              ? wsMode[hdl]
              : websocketpp::frame::opcode::text;
        server->send(hdl, helpers::jsonToString(message), op);
        return true;
    }
    return false;
}

void broadcastToAllExtensions(const json &message) {
    for (const auto &[_, connection]: extConnections) {
        auto op = wsMode.count(connection)
            ? wsMode[connection]
            : websocketpp::frame::opcode::text;
        server->send(connection, helpers::jsonToString(message), op);
    }
}

void broadcastToAllApps(const json &message) {
    for (const auto &connection: appConnections) {
        server->send(connection, helpers::jsonToString(message), websocketpp::frame::opcode::text);
    }
}

vector<string> getConnectedExtensions() {
    vector<string> extensions;
    for (const auto &[extensionId, _]: extConnections) {
        extensions.push_back(extensionId);
    }
    return extensions;
}

string getDocumentRoot() {
    string documentRoot = "";
    json jDocumentRoot = settings::getOptionForCurrentMode("documentRoot");
    if(!jDocumentRoot.is_null()) {
        documentRoot = jDocumentRoot.get<string>();
        
        if(documentRoot.back() == '/') {
            documentRoot.pop_back();
        }
    }
    return documentRoot;
}

string getHostAddress() {
    return serverHost;
}

} // namespace neuserver
