// HypeLLM Monitor: a Windows 11 tray companion for the HypeLLM Router.
//
// It polls the router's management API with a `management:read` key, shows
// which models have requests in flight and how fast tokens are moving per
// user and per key, and does so at the lowest scheduling class the OS
// offers, in the manner of HypeLimits.

#include "json.hpp"
#include "model.hpp"

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000C
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>
#include <processthreadsapi.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <winhttp.h>
#include <wincred.h>
#include <uxtheme.h>

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#endif
#ifndef PROCESS_POWER_THROTTLING_EXECUTION_SPEED
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif
#ifndef THREAD_POWER_THROTTLING_CURRENT_VERSION
#define THREAD_POWER_THROTTLING_CURRENT_VERSION 1
#endif
#ifndef THREAD_POWER_THROTTLING_EXECUTION_SPEED
#define THREAD_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif
#ifndef MEMORY_PRIORITY_LOW
#define MEMORY_PRIORITY_LOW 2
#endif
// THREAD_POWER_THROTTLING_STATE is missing from some SDK headers (MinGW's
// among them); this is the documented layout and the ThreadPowerThrottling
// information class it is passed with.
struct ThreadPowerThrottlingState {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
};
constexpr auto kThreadPowerThrottlingClass = static_cast<THREAD_INFORMATION_CLASS>(3);
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace hypellm_monitor;

namespace {

constexpr wchar_t kAppName[] = L"HypeLLM Monitor";
constexpr wchar_t kRegistryKey[] = L"Software\\HypeLLM\\Monitor";
constexpr wchar_t kCredentialTarget[] = L"HypeLLM/Monitor/ManagementKey";
constexpr wchar_t kUserAgent[] = L"HypeLLM-Monitor/0.1";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kRefreshCompleteMessage = WM_APP + 2;
constexpr UINT_PTR kPollTimer = 1;
// Armed for every refresh and cleared when its completion message arrives. The
// worker cannot schedule the next poll itself - a timer belongs to the thread
// that owns the window - so if its `PostMessageW` fails, this is what notices
// that the refresh ended without a completion and keeps polling alive.
constexpr UINT_PTR kRefreshWatchdogTimer = 2;
constexpr UINT kRefreshWatchdogMillis = 5000;
constexpr int kMonitorLogicalMinWidth = 200;
constexpr int kMonitorMinWindowWidth = 140;
constexpr int kMonitorResizeEdge = 8;
constexpr int kMonitorCorner = 14;
constexpr int kMonitorFontPx = 16;
constexpr int kMonitorSmallFontPx = 13;
constexpr int kMonitorDefaultWidth = 250;
constexpr int kMonitorClickSlop = 4;
constexpr DWORD kDefaultPollSeconds = 2;
constexpr DWORD kDefaultWindowSeconds = 60;
constexpr std::size_t kMaxBodyBytes = 4 * 1024 * 1024;

constexpr COLORREF kBackground = RGB(31, 33, 39);
constexpr COLORREF kEditBackground = RGB(45, 48, 56);
constexpr COLORREF kText = RGB(232, 233, 236);
constexpr COLORREF kTextActive = RGB(248, 250, 252);
constexpr COLORREF kTextDim = RGB(148, 152, 160);
constexpr COLORREF kHeading = RGB(120, 126, 138);
constexpr COLORREF kTrackActive = RGB(78, 82, 94);
constexpr COLORREF kTrackIdle = RGB(46, 48, 56);
constexpr COLORREF kAuthRowBackground = RGB(118, 58, 14);
constexpr COLORREF kAuthRowText = RGB(255, 196, 96);
constexpr COLORREF kDownRowBackground = RGB(96, 30, 30);
constexpr COLORREF kDownRowText = RGB(255, 170, 160);
constexpr COLORREF kThroughputFill = RGB(64, 196, 255);
// A model row the router says is not available, and one it says is recovering.
// Activity alone cannot carry this: a quiet target and a quarantined one draw
// identically when brightness is the only signal, and the second is the row
// the panel was opened for.
constexpr COLORREF kUnavailableText = RGB(255, 138, 128);
constexpr COLORREF kRecoveringText = RGB(255, 196, 96);

enum ControlId {
    IdBaseUrlLabel = 100,
    IdBaseUrl,
    IdKeyLabel,
    IdKey,
    IdKeyState,
    IdClearKey,
    IdPollLabel,
    IdPoll,
    IdWindowLabel,
    IdWindow,
    IdAlwaysOnTop,
    IdLaunchAtLogin,
    IdShowAllModels,
    IdShowUsers,
    IdShowKeys,
    IdRefresh,
    IdOpenConsole,
    IdStatus,
    IdClose,
    IdTrayShow = 300,
    IdTrayRefresh,
    IdTrayConsole,
    IdTrayOptions,
    IdTrayQuit,
};

std::string narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring wide(std::string_view value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

DWORD readDword(const wchar_t* name, DWORD fallback) {
    DWORD value = fallback;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, kRegistryKey, name, RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS) return fallback;
    return value;
}

void writeDword(const wchar_t* name, DWORD value) {
    HKEY key{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(key);
    }
}

std::wstring readString(const wchar_t* name, std::wstring fallback) {
    DWORD size = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, kRegistryKey, name, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS || size < sizeof(wchar_t)) return fallback;
    std::wstring value(size / sizeof(wchar_t), L'\0');
    if (RegGetValueW(HKEY_CURRENT_USER, kRegistryKey, name, RRF_RT_REG_SZ, nullptr, value.data(), &size) != ERROR_SUCCESS) return fallback;
    while (!value.empty() && value.back() == L'\0') value.pop_back();
    return value;
}

void writeString(const wchar_t* name, const std::wstring& value) {
    HKEY key{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                       static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
}

// The management key lives in Credential Manager, never in the registry or
// a settings file, and is zeroed after every use.
std::string loadKey() {
    PCREDENTIALW credential{};
    if (!CredReadW(kCredentialTarget, CRED_TYPE_GENERIC, 0, &credential)) return {};
    std::string key(reinterpret_cast<const char*>(credential->CredentialBlob), credential->CredentialBlobSize);
    SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
    CredFree(credential);
    return key;
}

bool saveKey(const std::string& key) {
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<wchar_t*>(kCredentialTarget);
    credential.CredentialBlobSize = static_cast<DWORD>(key.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(key.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<wchar_t*>(L"management:read");
    return CredWriteW(&credential, 0) != FALSE;
}

bool hasKey() {
    PCREDENTIALW credential{};
    if (!CredReadW(kCredentialTarget, CRED_TYPE_GENERIC, 0, &credential)) return false;
    const bool present = credential->CredentialBlobSize > 0;
    SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
    CredFree(credential);
    return present;
}

void deleteKey() {
    CredDeleteW(kCredentialTarget, CRED_TYPE_GENERIC, 0);
}

std::wstring currentExecutablePath() {
    wchar_t buffer[MAX_PATH * 4]{};
    const DWORD length = GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
    if (length == 0 || length >= std::size(buffer)) return {};
    return buffer;
}

bool setLaunchAtLogin(bool enabled) {
    HKEY key{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) return false;
    LONG result;
    if (enabled) {
        const std::wstring path = currentExecutablePath();
        if (path.empty()) { RegCloseKey(key); return false; }
        const std::wstring quoted = L"\"" + path + L"\"";
        result = RegSetValueExW(key, kAppName, 0, REG_SZ, reinterpret_cast<const BYTE*>(quoted.c_str()),
                                static_cast<DWORD>((quoted.size() + 1) * sizeof(wchar_t)));
    } else {
        result = RegDeleteValueW(key, kAppName);
        if (result == ERROR_FILE_NOT_FOUND) result = ERROR_SUCCESS;
    }
    RegCloseKey(key);
    if (result == ERROR_SUCCESS) writeDword(L"LaunchAtLogin", enabled ? 1 : 0);
    return result == ERROR_SUCCESS;
}

// Re-registers the autostart command if the executable moved. Does not
// change the user's choice.
void syncLaunchAtLoginPath() {
    if (!readDword(L"LaunchAtLogin", 0)) return;
    const std::wstring exe = currentExecutablePath();
    if (exe.empty()) return;
    wchar_t registered[MAX_PATH * 4]{};
    DWORD size = sizeof(registered);
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", kAppName, RRF_RT_REG_SZ,
                     nullptr, registered, &size) == ERROR_SUCCESS) {
        std::wstring current(registered);
        if (current.size() >= 2 && current.front() == L'"' && current.back() == L'"') current = current.substr(1, current.size() - 2);
        if (_wcsicmp(current.c_str(), exe.c_str()) == 0) return;
    }
    setLaunchAtLogin(true);
}

struct Endpoint {
    std::wstring host;
    INTERNET_PORT port{};
    bool secure{false};
    std::wstring pathPrefix;
};

// Only the scheme, host, port and an optional path prefix are taken from the
// address the user typed; the API paths themselves are fixed here.
std::optional<Endpoint> parseBaseUrl(std::wstring url) {
    while (!url.empty() && (url.back() == L' ' || url.back() == L'/')) url.pop_back();
    while (!url.empty() && url.front() == L' ') url.erase(url.begin());
    if (url.empty()) return std::nullopt;
    if (url.find(L"://") == std::wstring::npos) url = L"http://" + url;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256]{};
    wchar_t path[1024]{};
    parts.lpszHostName = host;
    parts.dwHostNameLength = static_cast<DWORD>(std::size(host));
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = static_cast<DWORD>(std::size(path));
    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts)) return std::nullopt;
    if (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS) return std::nullopt;
    if (parts.dwHostNameLength == 0) return std::nullopt;
    Endpoint endpoint;
    endpoint.host.assign(host, parts.dwHostNameLength);
    endpoint.port = parts.nPort;
    endpoint.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    endpoint.pathPrefix.assign(path, parts.dwUrlPathLength);
    if (endpoint.pathPrefix == L"/") endpoint.pathPrefix.clear();
    return endpoint;
}

struct HttpResponse {
    DWORD status{};
    std::string body;
    std::string error;
};

// No proxy, ever: the router is a service on this machine or on the LAN, and
// a management key must not be handed to whatever the system proxy is.
HttpResponse httpGet(HINTERNET session, const Endpoint& endpoint, std::wstring_view path, const std::string& key) {
    HttpResponse result;
    HINTERNET connection = WinHttpConnect(session, endpoint.host.c_str(), endpoint.port, 0);
    if (!connection) { result.error = "Could not open a connection."; return result; }
    const std::wstring fullPath = endpoint.pathPrefix + std::wstring(path);
    HINTERNET request = WinHttpOpenRequest(connection, L"GET", fullPath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, endpoint.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!request) {
        WinHttpCloseHandle(connection);
        result.error = "Could not create the request.";
        return result;
    }
    DWORD disable = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES;
    WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable));
    std::wstring headers = L"Authorization: Bearer " + wide(key) + L"\r\nAccept: application/json\r\n";
    const BOOL sent = WinHttpAddRequestHeaders(request, headers.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)
                   && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                   && WinHttpReceiveResponse(request, nullptr);
    SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
    if (sent) {
        DWORD statusSize = sizeof(result.status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                            &result.status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        while (result.body.size() < kMaxBodyBytes) {
            DWORD available{};
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
            const auto oldSize = result.body.size();
            result.body.resize(oldSize + std::min<std::size_t>(available, kMaxBodyBytes - oldSize));
            DWORD read{};
            if (!WinHttpReadData(request, result.body.data() + oldSize, static_cast<DWORD>(result.body.size() - oldSize), &read)) {
                result.body.resize(oldSize);
                break;
            }
            result.body.resize(oldSize + read);
        }
    } else {
        const DWORD code = GetLastError();
        char buffer[96]{};
        const char* reason = "The request failed";
        switch (code) {
        case ERROR_WINHTTP_CANNOT_CONNECT: reason = "Nothing is listening at that address"; break;
        case ERROR_WINHTTP_TIMEOUT: reason = "The router did not answer in time"; break;
        case ERROR_WINHTTP_NAME_NOT_RESOLVED: reason = "The host name could not be resolved"; break;
        case ERROR_WINHTTP_SECURE_FAILURE: reason = "The TLS certificate was not accepted"; break;
        case ERROR_WINHTTP_CONNECTION_ERROR: reason = "The connection was reset"; break;
        default: break;
        }
        std::snprintf(buffer, sizeof(buffer), "%s (WinHTTP %lu)", reason, static_cast<unsigned long>(code));
        result.error = buffer;
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    return result;
}

struct RefreshResult {
    ConnectionState state{ConnectionState::Refreshing};
    std::string diagnostic;
    std::optional<TrafficSnapshot> traffic;
    std::optional<UsageSnapshot> usage;
    std::optional<std::vector<TargetInfo>> targets;
    std::optional<SessionInfo> session;
    std::optional<OverviewInfo> overview;
    ULONGLONG tick{};
};

struct RefreshPlan {
    Endpoint endpoint;
    std::string key;
    bool wantSession{false};
    bool wantTargets{false};
};

// One poll. A refusal on the first call decides the state for the whole
// cycle; a later one is reported but the data already fetched is kept.
RefreshResult runRefresh(const RefreshPlan& plan) {
    RefreshResult result;
    HINTERNET session = WinHttpOpen(kUserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        result.state = ConnectionState::Unreachable;
        result.diagnostic = "Could not initialise Windows networking.";
        return result;
    }
    WinHttpSetTimeouts(session, 3000, 3000, 5000, 5000);

    auto classify = [&](const HttpResponse& response) -> bool {
        if (!response.error.empty()) {
            result.state = ConnectionState::Unreachable;
            result.diagnostic = response.error;
            return false;
        }
        if (response.status == 401) {
            result.state = ConnectionState::AuthenticationRequired;
            result.diagnostic = parseErrorMessage(response.body).value_or("The router refused the management key.");
            return false;
        }
        if (response.status == 403) {
            result.state = ConnectionState::Forbidden;
            result.diagnostic = parseErrorMessage(response.body).value_or("The key's principal lacks the permission this view needs.");
            return false;
        }
        if (response.status < 200 || response.status >= 300) {
            result.state = ConnectionState::Malformed;
            char buffer[64]{};
            std::snprintf(buffer, sizeof(buffer), "HTTP %lu from the router", static_cast<unsigned long>(response.status));
            result.diagnostic = parseErrorMessage(response.body).value_or(buffer);
            return false;
        }
        return true;
    };
    auto fetch = [&](std::wstring_view path) -> std::optional<JsonValue> {
        const HttpResponse response = httpGet(session, plan.endpoint, path, plan.key);
        if (!classify(response)) return std::nullopt;
        auto parsed = parseJson(response.body);
        if (!parsed) {
            result.state = ConnectionState::Malformed;
            result.diagnostic = "The reply to " + narrow(path) + " was not JSON the monitor understands.";
        }
        return parsed;
    };

    result.state = ConnectionState::Connected;
    if (const auto traffic = fetch(L"/admin/v1/traffic")) {
        result.traffic = parseTraffic(*traffic);
        if (!result.traffic) {
            result.state = ConnectionState::Malformed;
            result.diagnostic = "The traffic view is missing its capacity section.";
        }
    }
    const bool trafficOk = result.state == ConnectionState::Connected;
    if (trafficOk) {
        if (const auto usage = fetch(L"/admin/v1/usage")) {
            result.usage = parseUsage(*usage);
            if (!result.usage) {
                result.state = ConnectionState::Malformed;
                result.diagnostic = "The usage view is missing its rows.";
            }
        }
    }
    if (result.state == ConnectionState::Connected && plan.wantSession) {
        if (const auto session = fetch(L"/admin/v1/session")) result.session = parseSession(*session);
    }
    if (result.state == ConnectionState::Connected && plan.wantTargets) {
        // The default page is 50 rows and the monitor follows no cursor. A
        // deployment past that would silently lose the tail - and now that the
        // listing decides which models are shown as available, a lost row is a
        // model missing from the panel, not just an unlabelled one. 500 is the
        // server's own maximum.
        if (const auto targets = fetch(L"/admin/v1/targets?limit=500")) result.targets = parseTargets(*targets);
        if (result.state == ConnectionState::Connected) {
            if (const auto overview = fetch(L"/admin/v1/overview")) result.overview = parseOverview(*overview);
        }
    }
    WinHttpCloseHandle(session);
    return result;
}

std::wstring formatAgo(ULONGLONG tick, ULONGLONG nowTick) {
    if (tick == 0) return L"never";
    const ULONGLONG ago = nowTick >= tick ? (nowTick - tick) / 1000 : 0;
    return std::to_wstring(ago) + L" s ago";
}

struct MonitorHit {
    RECT rect;
    std::size_t row;
};

class App {
public:
    bool initialize(HINSTANCE instance);
    int run();
    void showOptionsWindow() { showOptions(); }

private:
    static LRESULT CALLBACK trayProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK floatingProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK optionsProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onTray(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onFloating(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onOptions(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    void applyLowSystemPriorities();
    static void applyWorkerPriorities();

    void loadSettings();
    void refresh();
    void scheduleNextPoll(bool failed);
    void onRefreshComplete(RefreshResult* result);
    MonitorInput monitorInput() const;
    MonitorOptions monitorOptions() const;

    void updateAll();
    void rebuildRows();
    void layoutMonitor();
    void syncFloatingWindowSize();
    void renderMonitorBitmap();
    void destroyMonitorBitmap();
    void paintFloating();
    double monitorScale() const;
    POINT toLogical(POINT client) const;
    enum class ResizeEdge { None, Right, Bottom, Corner };
    ResizeEdge resizeEdgeAt(POINT client) const;
    const MonitorHit* hitAt(POINT client) const;
    void activateTooltip(POINT clientPoint);
    void handleMonitorClick(POINT client);

    HICON createGaugeIcon(const TraySummary& summary);
    void installTrayIcon();
    void updateTrayIcon();
    void showTrayMenu();
    void toggleMonitor();
    void openConsole();

    void createOptionsControls();
    void layoutOptions(int width, int height);
    void showOptions();
    void updateOptions();
    void persistOptions();
    void applyCheckbox(int id);
    std::wstring statusReport() const;

    HINSTANCE instance_{};
    HWND trayWindow_{};
    HWND floatingWindow_{};
    HWND optionsWindow_{};
    HWND tooltip_{};
    HFONT font_{};
    HBRUSH darkBrush_{};
    HBRUSH editBrush_{};
    HICON trayIcon_{};
    UINT taskbarCreatedMessage_{};

    // Options controls.
    HWND baseUrlLabel_{}, baseUrl_{}, keyLabel_{}, key_{}, keyState_{}, clearKey_{};
    HWND pollLabel_{}, poll_{}, windowLabel_{}, window_{};
    HWND alwaysOnTop_{}, launchAtLogin_{}, showAll_{}, showUsers_{}, showKeys_{};
    HWND refreshButton_{}, openConsole_{}, status_{}, close_{};

    // Settings.
    std::wstring baseUrlText_;
    std::optional<Endpoint> endpoint_;
    bool keyPresent_{false};
    DWORD pollSeconds_{kDefaultPollSeconds};
    DWORD windowSeconds_{kDefaultWindowSeconds};

    // Live state.
    ConnectionState state_{ConnectionState::NotConfigured};
    std::string diagnostic_;
    std::optional<TrafficSnapshot> traffic_;
    std::optional<UsageSnapshot> usage_;
    std::vector<TargetInfo> targets_;
    std::optional<SessionInfo> session_;
    std::optional<OverviewInfo> overview_;
    RateBook rates_{kDefaultWindowSeconds * 1000};
    ULONGLONG lastSuccessTick_{};
    ULONGLONG lastAttemptTick_{};
    unsigned pollsSinceTargets_{0};
    bool sessionKnown_{false};
    unsigned failureStreak_{0};
    std::atomic_bool refreshing_{false};
    std::jthread refreshThread_;

    // Monitor rendering.
    std::vector<MonitorRow> rows_;
    std::vector<MonitorHit> hits_;
    std::vector<int> rowTops_;
    std::vector<int> rowHeights_;
    int logicalWidth_{kMonitorDefaultWidth};
    int logicalHeight_{48};
    HBITMAP monitorBitmap_{};
    void* monitorBits_{};
    int monitorBmpW_{0};
    int monitorBmpH_{0};
    bool dragging_{false};
    bool resizing_{false};
    ResizeEdge resizeEdge_{ResizeEdge::None};
    POINT dragStart_{};
    POINT windowStart_{};
    POINT resizeCursorStart_{};
    int resizeStartWidth_{0};
};

void App::applyLowSystemPriorities() {
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    SetProcessPriorityBoost(GetCurrentProcess(), TRUE);

    MEMORY_PRIORITY_INFORMATION memory{};
    memory.MemoryPriority = MEMORY_PRIORITY_LOW;
    SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &memory, sizeof(memory));

    PROCESS_POWER_THROTTLING_STATE power{};
    power.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    power.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    power.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power, sizeof(power));

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
}

void App::applyWorkerPriorities() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);

    ThreadPowerThrottlingState power{};
    power.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
    power.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    power.StateMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    SetThreadInformation(GetCurrentThread(), kThreadPowerThrottlingClass, &power, sizeof(power));
}

void App::loadSettings() {
    baseUrlText_ = readString(L"BaseUrl", L"");
    endpoint_ = parseBaseUrl(baseUrlText_);
    keyPresent_ = hasKey();
    pollSeconds_ = std::clamp<DWORD>(readDword(L"PollSeconds", kDefaultPollSeconds), 1, 3600);
    windowSeconds_ = std::clamp<DWORD>(readDword(L"RateWindowSeconds", kDefaultWindowSeconds), 5, 3600);
    rates_.setWindow(static_cast<Millis>(windowSeconds_) * 1000);
    if (!endpoint_ || !keyPresent_) {
        state_ = ConnectionState::NotConfigured;
    } else if (state_ == ConnectionState::NotConfigured) {
        state_ = ConnectionState::Refreshing;
    }
}

bool App::initialize(HINSTANCE instance) {
    instance_ = instance;
    applyLowSystemPriorities();
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&controls);
    darkBrush_ = CreateSolidBrush(kBackground);
    editBrush_ = CreateSolidBrush(kEditBackground);
    font_ = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    const WNDCLASSEXW floatingClass{sizeof(WNDCLASSEXW), CS_DBLCLKS, floatingProc, 0, 0, instance_, nullptr,
        LoadCursorW(nullptr, IDC_ARROW), nullptr, nullptr, L"HypeLLMMonitorFloating", nullptr};
    const WNDCLASSEXW optionsClass{sizeof(WNDCLASSEXW), CS_DBLCLKS, optionsProc, 0, 0, instance_, nullptr,
        LoadCursorW(nullptr, IDC_ARROW), darkBrush_, nullptr, L"HypeLLMMonitorOptions", nullptr};
    const WNDCLASSEXW trayClass{sizeof(WNDCLASSEXW), 0, trayProc, 0, 0, instance_, nullptr,
        nullptr, nullptr, nullptr, L"HypeLLMMonitorTray", nullptr};
    if (!RegisterClassExW(&floatingClass) || !RegisterClassExW(&optionsClass) || !RegisterClassExW(&trayClass)) return false;

    loadSettings();

    trayWindow_ = CreateWindowExW(0, trayClass.lpszClassName, kAppName, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, instance_, this);
    taskbarCreatedMessage_ = RegisterWindowMessageW(L"TaskbarCreated");
    const int x = static_cast<int>(readDword(L"MonitorX", 30));
    const int y = static_cast<int>(readDword(L"MonitorY", 30));
    const int width = std::max(static_cast<int>(readDword(L"MonitorWidth", kMonitorDefaultWidth)), kMonitorMinWindowWidth);
    floatingWindow_ = CreateWindowExW(WS_EX_TOOLWINDOW | (readDword(L"AlwaysOnTop", 1) ? WS_EX_TOPMOST : 0),
        floatingClass.lpszClassName, kAppName, WS_POPUP, x, y, width, 80, nullptr, nullptr, instance_, this);
    optionsWindow_ = CreateWindowExW(WS_EX_APPWINDOW, optionsClass.lpszClassName, L"HypeLLM Monitor Options",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 720, nullptr, nullptr, instance_, this);
    if (!trayWindow_ || !floatingWindow_ || !optionsWindow_) return false;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(optionsWindow_, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    createOptionsControls();
    RECT optionsClient{};
    GetClientRect(optionsWindow_, &optionsClient);
    layoutOptions(optionsClient.right, optionsClient.bottom);
    installTrayIcon();
    syncLaunchAtLoginPath();

    updateAll();
    RECT monitorRect{};
    GetWindowRect(floatingWindow_, &monitorRect);
    if (!MonitorFromRect(&monitorRect, MONITOR_DEFAULTTONULL)) SetWindowPos(floatingWindow_, nullptr, 30, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    if (readDword(L"MonitorVisible", 1)) ShowWindow(floatingWindow_, SW_SHOWNOACTIVATE);

    if (!readDword(L"FirstRunComplete", 0)) {
        // Asked once, as HypeLimits does; declining is not asked again, and
        // Options can change the answer later.
        const int answer = MessageBoxW(optionsWindow_,
            L"Would you like HypeLLM Monitor to start automatically when you log in?\n\nYou can change this later in Options.",
            L"Start HypeLLM Monitor at login?", MB_ICONQUESTION | MB_YESNO);
        if (answer == IDYES && !setLaunchAtLogin(true)) {
            MessageBoxW(optionsWindow_, L"Windows rejected the launch-at-login change.", kAppName, MB_ICONWARNING);
        }
        writeDword(L"FirstRunComplete", 1);
        showOptions();
    }
    refresh();
    return true;
}

int App::run() {
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (IsWindowVisible(optionsWindow_) && IsDialogMessageW(optionsWindow_, &message)) continue;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

MonitorOptions App::monitorOptions() const {
    MonitorOptions options;
    options.showAllModels = readDword(L"ShowAllModels", 1) != 0;
    options.showPrincipals = readDword(L"ShowUsers", 1) != 0;
    options.showKeys = readDword(L"ShowKeys", 1) != 0;
    return options;
}

MonitorInput App::monitorInput() const {
    MonitorInput input;
    input.state = state_;
    input.diagnostic = diagnostic_;
    input.traffic = traffic_;
    input.usage = usage_;
    input.targets = targets_;
    input.rates = &rates_;
    input.now = GetTickCount64();
    return input;
}

void App::refresh() {
    if (!endpoint_ || !keyPresent_) {
        state_ = ConnectionState::NotConfigured;
        updateAll();
        return;
    }
    if (refreshing_.exchange(true)) return;
    if (refreshThread_.joinable()) refreshThread_.join();
    RefreshPlan plan;
    plan.endpoint = *endpoint_;
    plan.key = loadKey();
    plan.wantSession = !sessionKnown_;
    plan.wantTargets = targets_.empty() || pollsSinceTargets_ >= 15;
    lastAttemptTick_ = GetTickCount64();
    if (state_ == ConnectionState::NotConfigured) state_ = ConnectionState::Refreshing;
    refreshThread_ = std::jthread([this, plan = std::move(plan)]() mutable {
        applyWorkerPriorities();
        auto result = std::make_unique<RefreshResult>(runRefresh(plan));
        SecureZeroMemory(plan.key.data(), plan.key.size());
        result->tick = GetTickCount64();
        auto* completed = result.release();
        if (!PostMessageW(trayWindow_, kRefreshCompleteMessage, 0, reinterpret_cast<LPARAM>(completed))) {
            delete completed;
            refreshing_ = false;
        }
    });
    SetTimer(trayWindow_, kRefreshWatchdogTimer, kRefreshWatchdogMillis, nullptr);
}

void App::scheduleNextPoll(bool failed) {
    failureStreak_ = failed ? std::min(failureStreak_ + 1, 5U) : 0U;
    const ULONGLONG base = static_cast<ULONGLONG>(pollSeconds_) * 1000ULL;
    const ULONGLONG backoff = failed ? std::min<ULONGLONG>(base * (1ULL << failureStreak_), 60000ULL) : base;
    const ULONGLONG jitter = failed ? GetTickCount64() % 1001ULL : 0;
    SetTimer(trayWindow_, kPollTimer, static_cast<UINT>(std::min<ULONGLONG>(std::max<ULONGLONG>(backoff + jitter, 250), 0xFFFFFFFEULL)), nullptr);
}

void App::onRefreshComplete(RefreshResult* raw) {
    std::unique_ptr<RefreshResult> result(raw);
    KillTimer(trayWindow_, kRefreshWatchdogTimer);
    refreshing_ = false;
    state_ = result->state;
    diagnostic_ = result->diagnostic;
    const bool succeeded = result->state == ConnectionState::Connected;
    if (result->traffic) traffic_ = std::move(result->traffic);
    if (result->usage) {
        usage_ = std::move(result->usage);
        rates_.observe(*usage_, result->tick);
    }
    if (result->targets) {
        targets_ = std::move(*result->targets);
        pollsSinceTargets_ = 0;
    } else {
        ++pollsSinceTargets_;
    }
    if (result->session) {
        session_ = std::move(result->session);
        sessionKnown_ = true;
    }
    if (result->overview) overview_ = std::move(result->overview);
    if (succeeded) lastSuccessTick_ = result->tick;
    if (result->state == ConnectionState::AuthenticationRequired || result->state == ConnectionState::Forbidden) sessionKnown_ = false;
    updateAll();
    scheduleNextPoll(!succeeded);
}

void App::updateAll() {
    rebuildRows();
    destroyMonitorBitmap();
    syncFloatingWindowSize();
    InvalidateRect(floatingWindow_, nullptr, FALSE);
    updateTrayIcon();
    if (IsWindowVisible(optionsWindow_)) updateOptions();
}

void App::rebuildRows() {
    rows_ = buildMonitorRows(monitorInput(), monitorOptions());
}

double App::monitorScale() const {
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    return static_cast<double>(std::max(1, static_cast<int>(client.right))) / static_cast<double>(std::max(1, logicalWidth_));
}

POINT App::toLogical(POINT client) const {
    const double scale = monitorScale();
    return {static_cast<int>(std::lround(client.x / scale)), static_cast<int>(std::lround(client.y / scale))};
}

App::ResizeEdge App::resizeEdgeAt(POINT client) const {
    RECT bounds{};
    GetClientRect(floatingWindow_, &bounds);
    const bool right = client.x >= bounds.right - kMonitorResizeEdge;
    const bool bottom = client.y >= bounds.bottom - kMonitorResizeEdge;
    if (right && bottom) return ResizeEdge::Corner;
    if (right) return ResizeEdge::Right;
    if (bottom) return ResizeEdge::Bottom;
    return ResizeEdge::None;
}

const MonitorHit* App::hitAt(POINT client) const {
    const POINT logical = toLogical(client);
    for (const auto& hit : hits_) {
        if (PtInRect(&hit.rect, logical)) return &hit;
    }
    return nullptr;
}

namespace {

// Row geometry in logical pixels, shared with `stackRows` in the portable
// core so the stacking is tested on any host.
constexpr int kHeadingHeight = kRowHeadingHeight;
constexpr int kLabelHeight = kRowLabelHeight;
constexpr int kBarHeight = kRowBarHeight;
constexpr int kSidePad = 10;

HFONT makeFont(int px, int weight = FW_NORMAL) {
    return CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

} // namespace

void App::layoutMonitor() {
    hits_.clear();
    rowTops_.clear();
    rowHeights_.clear();
    std::vector<int> wrapped(rows_.size(), 0);
    HDC dc = GetDC(floatingWindow_);
    if (dc) {
        HFONT small = makeFont(kMonitorSmallFontPx);
        const auto oldFont = SelectObject(dc, font_);
        int maxText = 0;
        for (const auto& row : rows_) {
            const std::wstring label = wide(row.label);
            const std::wstring caption = wide(row.caption);
            SIZE labelSize{};
            GetTextExtentPoint32W(dc, label.c_str(), static_cast<int>(label.size()), &labelSize);
            int need = static_cast<int>(labelSize.cx);
            if (!caption.empty()) {
                SelectObject(dc, small);
                SIZE captionSize{};
                GetTextExtentPoint32W(dc, caption.c_str(), static_cast<int>(caption.size()), &captionSize);
                SelectObject(dc, font_);
                need += static_cast<int>(captionSize.cx) + 14;
            }
            if (row.kind == RowKind::Status) need = std::min(need, 260);
            maxText = std::max(maxText, need);
        }
        logicalWidth_ = std::max(kMonitorLogicalMinWidth, maxText + 2 * kSidePad);

        for (std::size_t index = 0; index < rows_.size(); ++index) {
            if (rows_[index].kind != RowKind::Status) continue;
            const std::wstring label = wide(rows_[index].label);
            RECT wrap{kSidePad, 0, logicalWidth_ - kSidePad, 0};
            DrawTextW(dc, label.c_str(), -1, &wrap, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
            wrapped[index] = static_cast<int>(wrap.bottom);
        }
        SelectObject(dc, oldFont);
        DeleteObject(small);
        ReleaseDC(floatingWindow_, dc);
    } else {
        // Nothing to measure text with: the minimum width, and one line per
        // status row. The geometry is still built for every row, because the
        // renderer indexes it by row - an early return here once left it empty
        // and the next paint read past its end.
        logicalWidth_ = kMonitorLogicalMinWidth;
    }

    RowStack stack = stackRows(rows_, 8, wrapped);
    for (std::size_t index = 0; index < rows_.size(); ++index) {
        const int y = stack.tops[index];
        if (rows_[index].kind != RowKind::Heading) {
            hits_.push_back({RECT{0, y - 2, logicalWidth_, y + stack.heights[index] - 2}, index});
        }
    }
    rowTops_ = std::move(stack.tops);
    rowHeights_ = std::move(stack.heights);
    logicalHeight_ = std::max(40, stack.bottom + 4);
}

void App::syncFloatingWindowSize() {
    layoutMonitor();
    RECT window{};
    GetWindowRect(floatingWindow_, &window);
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    int width = client.right - client.left;
    if (width <= 0) width = window.right - window.left;
    width = std::max(width, kMonitorMinWindowWidth);
    const int height = std::max(1, static_cast<int>(std::lround(
        static_cast<double>(logicalHeight_) * static_cast<double>(width) / static_cast<double>(logicalWidth_))));
    if (window.right - window.left != width || window.bottom - window.top != height) {
        SetWindowPos(floatingWindow_, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    const int corner = std::max(4, static_cast<int>(std::lround(kMonitorCorner * monitorScale())));
    SetWindowRgn(floatingWindow_, CreateRoundRectRgn(0, 0, width, height, corner, corner), TRUE);
}

void App::destroyMonitorBitmap() {
    if (monitorBitmap_) {
        DeleteObject(monitorBitmap_);
        monitorBitmap_ = nullptr;
        monitorBits_ = nullptr;
        monitorBmpW_ = 0;
        monitorBmpH_ = 0;
    }
}

void App::renderMonitorBitmap() {
    layoutMonitor();
    destroyMonitorBitmap();

    RECT client{};
    GetClientRect(floatingWindow_, &client);
    const int s = std::max(2, (std::max(1, static_cast<int>(client.right)) + logicalWidth_ - 1) / logicalWidth_);
    const int bmpW = logicalWidth_ * s;
    const int bmpH = logicalHeight_ * s;

    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = bmpW;
    info.bmiHeader.biHeight = -bmpH;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    HDC windowDc = GetDC(floatingWindow_);
    monitorBitmap_ = CreateDIBSection(windowDc, &info, DIB_RGB_COLORS, &monitorBits_, nullptr, 0);
    HDC mem = CreateCompatibleDC(windowDc);
    const auto oldBmp = SelectObject(mem, monitorBitmap_);
    HFONT drawFont = makeFont(kMonitorFontPx * s);
    HFONT smallFont = makeFont(kMonitorSmallFontPx * s);
    HFONT headingFont = makeFont(kMonitorSmallFontPx * s, FW_SEMIBOLD);
    const auto oldFont = SelectObject(mem, drawFont);

    RECT full{0, 0, bmpW, bmpH};
    FillRect(mem, &full, darkBrush_);
    SetBkMode(mem, TRANSPARENT);

    auto scaled = [s](RECT rect) { return RECT{rect.left * s, rect.top * s, rect.right * s, rect.bottom * s}; };
    auto fill = [&](RECT rect, COLORREF color) {
        HBRUSH brush = CreateSolidBrush(color);
        FillRect(mem, &rect, brush);
        DeleteObject(brush);
    };

    const bool authRow = state_ == ConnectionState::AuthenticationRequired || state_ == ConnectionState::Forbidden;
    const bool downRow = state_ == ConnectionState::Unreachable;

    // `layoutMonitor` builds one top and one height per row; checked anyway,
    // because an index past either is a read off the end of a vector.
    const std::size_t drawable = std::min({rows_.size(), rowTops_.size(), rowHeights_.size()});
    for (std::size_t index = 0; index < drawable; ++index) {
        const auto& row = rows_[index];
        const int y = rowTops_[index];
        const std::wstring label = wide(row.label);
        const std::wstring caption = wide(row.caption);
        switch (row.kind) {
        case RowKind::Heading: {
            SelectObject(mem, headingFont);
            SetTextColor(mem, kHeading);
            RECT rect = scaled({kSidePad, y + 2, logicalWidth_ - kSidePad, y + kHeadingHeight});
            DrawTextW(mem, label.c_str(), -1, &rect, DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
            break;
        }
        case RowKind::Status: {
            SelectObject(mem, drawFont);
            const int height = rowHeights_[index];
            const bool tinted = (authRow || downRow) && index == rows_.size() - 1;
            if (tinted) {
                fill(scaled({0, y - 2, logicalWidth_, y + height - 2}), authRow ? kAuthRowBackground : kDownRowBackground);
                SetTextColor(mem, authRow ? kAuthRowText : kDownRowText);
            } else {
                SetTextColor(mem, kTextDim);
            }
            RECT rect = scaled({kSidePad, y + 1, logicalWidth_ - kSidePad, y + height});
            DrawTextW(mem, label.c_str(), -1, &rect, DT_WORDBREAK | DT_NOPREFIX | DT_NOCLIP);
            break;
        }
        default: {
            SelectObject(mem, drawFont);
            // Availability decides the hue, activity the brightness. A row the
            // router says is unavailable is never dimmed into looking like a
            // quiet one.
            const COLORREF labelColor = row.availability == Availability::Unavailable ? kUnavailableText
                                      : row.availability == Availability::Recovering  ? kRecoveringText
                                      : row.active                                    ? kTextActive
                                                                                      : kTextDim;
            const COLORREF captionColor = row.availability == Availability::Unavailable ? kUnavailableText
                                        : row.availability == Availability::Recovering  ? kRecoveringText
                                        : row.active                                    ? kText
                                                                                        : kTextDim;
            SetTextColor(mem, labelColor);
            int captionWidth = 0;
            if (!caption.empty()) {
                SelectObject(mem, smallFont);
                SIZE size{};
                GetTextExtentPoint32W(mem, caption.c_str(), static_cast<int>(caption.size()), &size);
                captionWidth = size.cx / s + 6;
                RECT captionRect = scaled({kSidePad, y + 3, logicalWidth_ - kSidePad, y + kLabelHeight});
                SetTextColor(mem, captionColor);
                DrawTextW(mem, caption.c_str(), -1, &captionRect, DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX | DT_NOCLIP);
                SelectObject(mem, drawFont);
                SetTextColor(mem, labelColor);
            }
            // Clipped and ellipsised, not drawn past its rect: a label now
            // carries the machine as well as the model, and one too long for a
            // narrow window must end in an ellipsis rather than paint over the
            // rate to its right. The machine leads, so what survives the cut is
            // the half that says which target this is.
            RECT labelRect = scaled({kSidePad, y, logicalWidth_ - kSidePad - captionWidth, y + kLabelHeight});
            DrawTextW(mem, label.c_str(), -1, &labelRect, DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
            RECT bar = scaled({kSidePad + 2, y + kLabelHeight + 1, logicalWidth_ - kSidePad - 2, y + kLabelHeight + 1 + kBarHeight});
            fill(bar, row.active ? kTrackActive : kTrackIdle);
            if (row.fraction) {
                RECT filled = bar;
                filled.right = filled.left + static_cast<LONG>((filled.right - filled.left) * std::clamp(*row.fraction, 0.0, 1.0));
                RgbColor color = row.kind == RowKind::Model ? utilisationColor(*row.fraction)
                                                             : RgbColor{GetRValue(kThroughputFill), GetGValue(kThroughputFill), GetBValue(kThroughputFill)};
                color = applyActivity(color, row.active);
                fill(filled, RGB(color.red, color.green, color.blue));
            }
            break;
        }
        }
    }

    SelectObject(mem, oldFont);
    DeleteObject(drawFont);
    DeleteObject(smallFont);
    DeleteObject(headingFont);
    SelectObject(mem, oldBmp);
    DeleteDC(mem);
    ReleaseDC(floatingWindow_, windowDc);
    monitorBmpW_ = bmpW;
    monitorBmpH_ = bmpH;
}

void App::paintFloating() {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(floatingWindow_, &paint);
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    if (!monitorBitmap_) renderMonitorBitmap();
    if (monitorBitmap_ && client.right > 0 && client.bottom > 0) {
        HDC mem = CreateCompatibleDC(dc);
        const auto oldBmp = SelectObject(mem, monitorBitmap_);
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, nullptr);
        StretchBlt(dc, 0, 0, client.right, client.bottom, mem, 0, 0, monitorBmpW_, monitorBmpH_, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteDC(mem);
    }
    EndPaint(floatingWindow_, &paint);
}

void App::activateTooltip(POINT clientPoint) {
    const auto* found = hitAt(clientPoint);
    if (!found || rows_[found->row].tooltip.empty()) {
        SendMessageW(tooltip_, TTM_TRACKACTIVATE, FALSE, 0);
        return;
    }
    std::wstring text = wide(rows_[found->row].tooltip);
    TOOLINFOW info{sizeof(info)};
    info.hwnd = floatingWindow_;
    info.uId = 1;
    info.lpszText = text.data();
    SendMessageW(tooltip_, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&info));
    POINT screen = clientPoint;
    ClientToScreen(floatingWindow_, &screen);
    SendMessageW(tooltip_, TTM_TRACKPOSITION, 0, MAKELPARAM(screen.x + 16, screen.y + 18));
    SendMessageW(tooltip_, TTM_TRACKACTIVATE, TRUE, reinterpret_cast<LPARAM>(&info));
}

void App::handleMonitorClick(POINT client) {
    const auto* found = hitAt(client);
    if (!found || rows_[found->row].kind != RowKind::Status) return;
    if (state_ != ConnectionState::Connected) showOptions();
}

HICON App::createGaugeIcon(const TraySummary& summary) {
    constexpr int size = 32;
    BITMAPV5HEADER header{};
    header.bV5Size = sizeof(header);
    header.bV5Width = size;
    header.bV5Height = -size;
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x00FF0000;
    header.bV5GreenMask = 0x0000FF00;
    header.bV5BlueMask = 0x000000FF;
    header.bV5AlphaMask = 0xFF000000;
    void* raw{};
    HDC dc = GetDC(nullptr);
    HBITMAP colorBitmap = CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&header), DIB_RGB_COLORS, &raw, nullptr, 0);
    ReleaseDC(nullptr, dc);
    auto* pixels = static_cast<DWORD*>(raw);
    const DWORD color = 0xFF000000 | (static_cast<DWORD>(summary.color.red) << 16) | (static_cast<DWORD>(summary.color.green) << 8)
                      | static_cast<DWORD>(summary.color.blue);
    // The HypeLimits gauge ring; the centre dot is lit only while something is
    // in flight, so an idle router reads as an open ring.
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double dx = x - 15.5;
            const double dy = y - 15.5;
            const double radius = std::sqrt(dx * dx + dy * dy);
            const double angle = std::atan2(dy, dx);
            const bool gap = angle > 0.65 && angle < 2.49;
            if (radius >= 9.0 && radius <= 13.0 && !gap) pixels[y * size + x] = color;
            else if (summary.active && radius < 4.2) pixels[y * size + x] = color;
            else pixels[y * size + x] = 0;
        }
    }
    HBITMAP mask = CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO info{TRUE, 0, 0, mask, colorBitmap};
    HICON icon = CreateIconIndirect(&info);
    DeleteObject(mask);
    DeleteObject(colorBitmap);
    return icon;
}

void App::installTrayIcon() {
    if (trayIcon_) DestroyIcon(trayIcon_);
    trayIcon_ = createGaugeIcon(traySummary(monitorInput()));
    NOTIFYICONDATAW data{sizeof(data)};
    data.hWnd = trayWindow_;
    data.uID = 1;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = kTrayMessage;
    data.hIcon = trayIcon_;
    wcscpy_s(data.szTip, L"HypeLLM — not configured");
    Shell_NotifyIconW(NIM_ADD, &data);
    data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &data);
}

void App::updateTrayIcon() {
    const TraySummary summary = traySummary(monitorInput());
    HICON newIcon = createGaugeIcon(summary);
    NOTIFYICONDATAW data{sizeof(data)};
    data.hWnd = trayWindow_;
    data.uID = 1;
    data.uFlags = NIF_ICON | NIF_TIP;
    data.hIcon = newIcon;
    wcsncpy_s(data.szTip, wide(summary.tooltip).c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &data);
    if (trayIcon_) DestroyIcon(trayIcon_);
    trayIcon_ = newIcon;
}

void App::showTrayMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IdTrayShow, IsWindowVisible(floatingWindow_) ? L"Hide Monitor" : L"Show Monitor");
    AppendMenuW(menu, MF_STRING, IdTrayRefresh, L"Refresh now");
    AppendMenuW(menu, MF_STRING | (endpoint_ ? 0 : MF_GRAYED), IdTrayConsole, L"Open admin console");
    AppendMenuW(menu, MF_STRING, IdTrayOptions, L"Options...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IdTrayQuit, L"Quit");
    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(trayWindow_);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, cursor.x, cursor.y, 0, trayWindow_, nullptr);
    DestroyMenu(menu);
}

void App::toggleMonitor() {
    const bool visible = IsWindowVisible(floatingWindow_) != FALSE;
    ShowWindow(floatingWindow_, visible ? SW_HIDE : SW_SHOWNOACTIVATE);
    writeDword(L"MonitorVisible", visible ? 0 : 1);
}

void App::openConsole() {
    if (!endpoint_) return;
    std::wstring url = (endpoint_->secure ? L"https://" : L"http://") + endpoint_->host;
    const bool defaultPort = (endpoint_->secure && endpoint_->port == 443) || (!endpoint_->secure && endpoint_->port == 80);
    if (!defaultPort) url += L":" + std::to_wstring(endpoint_->port);
    url += endpoint_->pathPrefix + L"/";
    ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void App::createOptionsControls() {
    auto make = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
        HWND control = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, optionsWindow_,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        SetWindowTheme(control, L"DarkMode_Explorer", nullptr);
        return control;
    };
    baseUrlLabel_ = make(L"STATIC", L"Router management address (for example http://127.0.0.1:8081)", SS_LEFT, IdBaseUrlLabel);
    baseUrl_ = make(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, IdBaseUrl);
    keyLabel_ = make(L"STATIC", L"Management API key (needs the management:read scope)", SS_LEFT, IdKeyLabel);
    key_ = make(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, IdKey);
    keyState_ = make(L"STATIC", L"", SS_LEFT, IdKeyState);
    clearKey_ = make(L"BUTTON", L"Forget key", BS_PUSHBUTTON | WS_TABSTOP, IdClearKey);
    pollLabel_ = make(L"STATIC", L"Poll every (seconds)", SS_LEFT, IdPollLabel);
    poll_ = make(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_NUMBER, IdPoll);
    windowLabel_ = make(L"STATIC", L"Rate window (seconds)", SS_LEFT, IdWindowLabel);
    window_ = make(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_NUMBER, IdWindow);
    alwaysOnTop_ = make(L"BUTTON", L"Keep the monitor above other windows", BS_AUTOCHECKBOX | WS_TABSTOP, IdAlwaysOnTop);
    launchAtLogin_ = make(L"BUTTON", L"Start HypeLLM Monitor when I log in", BS_AUTOCHECKBOX | WS_TABSTOP, IdLaunchAtLogin);
    showAll_ = make(L"BUTTON", L"List every model, not only the busy ones", BS_AUTOCHECKBOX | WS_TABSTOP, IdShowAllModels);
    showUsers_ = make(L"BUTTON", L"Show tokens per second per user", BS_AUTOCHECKBOX | WS_TABSTOP, IdShowUsers);
    showKeys_ = make(L"BUTTON", L"Show tokens per second per key (tenant-wide keys only)", BS_AUTOCHECKBOX | WS_TABSTOP, IdShowKeys);
    refreshButton_ = make(L"BUTTON", L"Apply and refresh", BS_DEFPUSHBUTTON | WS_TABSTOP, IdRefresh);
    openConsole_ = make(L"BUTTON", L"Open admin console", BS_PUSHBUTTON | WS_TABSTOP, IdOpenConsole);
    status_ = make(L"EDIT", L"", WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, IdStatus);
    close_ = make(L"BUTTON", L"Close", BS_PUSHBUTTON | WS_TABSTOP, IdClose);
}

void App::layoutOptions(int width, int height) {
    const int pad = 14;
    const int lineHeight = 26;
    const int labelHeight = 20;
    const int inner = std::max(200, width - 2 * pad);
    int y = pad;
    auto place = [&](HWND control, int x, int top, int w, int h) {
        SetWindowPos(control, nullptr, x, top, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    };
    place(baseUrlLabel_, pad, y, inner, labelHeight); y += labelHeight + 2;
    place(baseUrl_, pad, y, inner, lineHeight); y += lineHeight + 10;
    place(keyLabel_, pad, y, inner, labelHeight); y += labelHeight + 2;
    place(key_, pad, y, inner - 130, lineHeight);
    place(clearKey_, pad + inner - 120, y, 120, lineHeight); y += lineHeight + 4;
    place(keyState_, pad, y, inner, labelHeight); y += labelHeight + 10;
    place(pollLabel_, pad, y + 3, 190, labelHeight);
    place(poll_, pad + 196, y, 70, lineHeight);
    place(windowLabel_, pad + 290, y + 3, 190, labelHeight);
    place(window_, pad + 486, y, 70, lineHeight); y += lineHeight + 10;
    for (HWND box : {alwaysOnTop_, launchAtLogin_, showAll_, showUsers_, showKeys_}) {
        place(box, pad, y, inner, 24);
        y += 26;
    }
    y += 6;
    place(refreshButton_, pad, y, 170, 30);
    place(openConsole_, pad + 180, y, 170, 30);
    place(close_, pad + inner - 110, y, 110, 30); y += 40;
    place(status_, pad, y, inner, std::max(80, height - y - pad));
}

void App::showOptions() {
    updateOptions();
    ShowWindow(optionsWindow_, SW_SHOW);
    RECT client{};
    GetClientRect(optionsWindow_, &client);
    layoutOptions(client.right, client.bottom);
    SetForegroundWindow(optionsWindow_);
}

std::wstring App::statusReport() const {
    std::wstring text;
    const ULONGLONG now = GetTickCount64();
    text += L"Connection: " + wide(connectionStateName(state_));
    if (!diagnostic_.empty() && state_ != ConnectionState::Connected) text += L" — " + wide(diagnostic_);
    text += L"\r\n";
    if (endpoint_) {
        text += L"Router: " + endpoint_->host + L":" + std::to_wstring(endpoint_->port) + (endpoint_->secure ? L" (TLS)" : L" (plain HTTP)") + L"\r\n";
    } else if (!baseUrlText_.empty()) {
        text += L"Router address is not a usable http:// or https:// URL.\r\n";
    }
    if (!keyPresent_) text += L"No management key is saved.\r\n";
    if (session_) {
        text += L"Signed in as " + wide(session_->principal) + L" in tenant " + wide(session_->tenant) + L" via " + wide(session_->authMethod) + L"\r\n";
        bool tenantUsage = false;
        for (const auto& permission : session_->permissions) if (permission == "read_tenant_usage") tenantUsage = true;
        text += tenantUsage ? L"Usage scope: whole tenant (per-key rates available)\r\n"
                            : L"Usage scope: this principal only (no per-key rates)\r\n";
    }
    if (overview_) {
        text += L"Policy digest " + wide(overview_->configDigest) + L", " + std::to_wstring(overview_->targetsHealthy) + L" of "
              + std::to_wstring(overview_->targetsTotal) + L" targets healthy\r\n";
    }
    text += L"Last successful refresh: " + formatAgo(lastSuccessTick_, now) + L"\r\n";
    if (traffic_) {
        if (traffic_->capacityAvailable) {
            text += L"In flight: " + std::to_wstring(traffic_->globalInFlight.value_or(0));
            if (traffic_->globalMaxConcurrency) text += L" of " + std::to_wstring(*traffic_->globalMaxConcurrency);
            text += L", " + std::to_wstring(traffic_->activeStreams) + L" streaming\r\n";
        } else {
            text += L"The router exposes no admission controller to the management API, so no occupancy can be shown.\r\n";
        }
        if (traffic_->minuteRequests) {
            text += L"Last minute: " + wide(formatCount(*traffic_->minuteRequests)) + L" requests, "
                  + wide(formatCount(traffic_->minuteInputTokens.value_or(0))) + L" in / "
                  + wide(formatCount(traffic_->minuteOutputTokens.value_or(0))) + L" out tokens\r\n";
        } else if (!traffic_->attributed) {
            text += L"The router dropped this tenant's traffic samples; no rate figures are available.\r\n";
        }
    }
    if (usage_ && usage_->truncated) text += L"The router's usage breakdown is truncated; some users are folded into an unattributed remainder.\r\n";
    text += L"\r\n";
    for (const auto& row : rows_) {
        switch (row.kind) {
        case RowKind::Heading: text += L"[" + wide(row.label) + L"]\r\n"; break;
        case RowKind::Status: text += wide(row.label) + L"\r\n"; break;
        default:
            text += L"  " + wide(row.label);
            if (!row.caption.empty()) text += L"  —  " + wide(row.caption);
            text += L"\r\n";
            break;
        }
    }
    text += L"\r\nRates are computed from the router's completed-request counters over the rate window, so a long stream shows when it finishes.";
    return text;
}

void App::updateOptions() {
    if (GetFocus() != baseUrl_) SetWindowTextW(baseUrl_, baseUrlText_.c_str());
    SetWindowTextW(keyState_, keyPresent_ ? L"A key is saved in Windows Credential Manager. Paste a new one to replace it."
                                          : L"No key saved. Create one with the management:read scope on the router's Keys screen.");
    ShowWindow(clearKey_, keyPresent_ ? SW_SHOW : SW_HIDE);
    if (GetFocus() != poll_) SetWindowTextW(poll_, std::to_wstring(pollSeconds_).c_str());
    if (GetFocus() != window_) SetWindowTextW(window_, std::to_wstring(windowSeconds_).c_str());
    Button_SetCheck(alwaysOnTop_, readDword(L"AlwaysOnTop", 1) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(launchAtLogin_, readDword(L"LaunchAtLogin", 0) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(showAll_, readDword(L"ShowAllModels", 1) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(showUsers_, readDword(L"ShowUsers", 1) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(showKeys_, readDword(L"ShowKeys", 1) ? BST_CHECKED : BST_UNCHECKED);
    EnableWindow(openConsole_, endpoint_ ? TRUE : FALSE);
    SetWindowTextW(status_, statusReport().c_str());
}

// Reads every field back, stores what changed, and resets the rate book when
// the router or the window changed so no rate spans two different worlds.
void App::persistOptions() {
    wchar_t buffer[2048]{};
    GetWindowTextW(baseUrl_, buffer, static_cast<int>(std::size(buffer)));
    std::wstring url(buffer);
    const bool urlChanged = url != baseUrlText_;
    if (urlChanged) {
        baseUrlText_ = url;
        writeString(L"BaseUrl", url);
    }

    GetWindowTextW(key_, buffer, static_cast<int>(std::size(buffer)));
    std::wstring typed(buffer);
    bool keyChanged = false;
    if (!typed.empty()) {
        std::string key = narrow(typed);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\r' || key.back() == '\n')) key.pop_back();
        if (!key.empty()) {
            if (saveKey(key)) keyChanged = true;
            else MessageBoxW(optionsWindow_, L"Windows Credential Manager refused to store the key.", kAppName, MB_ICONWARNING);
        }
        SecureZeroMemory(key.data(), key.size());
        SetWindowTextW(key_, L"");
    }
    SecureZeroMemory(typed.data(), typed.size() * sizeof(wchar_t));
    SecureZeroMemory(buffer, sizeof(buffer));

    GetWindowTextW(poll_, buffer, static_cast<int>(std::size(buffer)));
    const DWORD poll = std::clamp<DWORD>(static_cast<DWORD>(wcstoul(buffer, nullptr, 10)), 1, 3600);
    GetWindowTextW(window_, buffer, static_cast<int>(std::size(buffer)));
    const DWORD window = std::clamp<DWORD>(static_cast<DWORD>(wcstoul(buffer, nullptr, 10)), 5, 3600);
    writeDword(L"PollSeconds", poll);
    writeDword(L"RateWindowSeconds", window);
    const bool windowChanged = window != windowSeconds_;

    const bool pollChanged = poll != pollSeconds_;

    loadSettings();
    if (urlChanged || keyChanged || windowChanged) {
        rates_.clear();
        if (urlChanged || keyChanged) {
            traffic_.reset();
            usage_.reset();
            targets_.clear();
            session_.reset();
            overview_.reset();
            sessionKnown_ = false;
            lastSuccessTick_ = 0;
            diagnostic_.clear();
            if (endpoint_ && keyPresent_) state_ = ConnectionState::Refreshing;
        }
    }
    updateAll();
    // A changed router, key or cadence takes effect now, not at the next
    // tick - and when nothing was configured before, there is no next tick.
    if (urlChanged || keyChanged || pollChanged) {
        KillTimer(trayWindow_, kPollTimer);
        refresh();
    }
}

void App::applyCheckbox(int id) {
    switch (id) {
    case IdAlwaysOnTop: {
        const bool onTop = Button_GetCheck(alwaysOnTop_) == BST_CHECKED;
        writeDword(L"AlwaysOnTop", onTop ? 1 : 0);
        SetWindowPos(floatingWindow_, onTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        return;
    }
    case IdLaunchAtLogin: {
        const bool launch = Button_GetCheck(launchAtLogin_) == BST_CHECKED;
        if (!setLaunchAtLogin(launch)) {
            MessageBoxW(optionsWindow_, L"Windows rejected the launch-at-login change.", kAppName, MB_ICONWARNING);
            Button_SetCheck(launchAtLogin_, readDword(L"LaunchAtLogin", 0) ? BST_CHECKED : BST_UNCHECKED);
        }
        return;
    }
    case IdShowAllModels: writeDword(L"ShowAllModels", Button_GetCheck(showAll_) == BST_CHECKED ? 1 : 0); break;
    case IdShowUsers: writeDword(L"ShowUsers", Button_GetCheck(showUsers_) == BST_CHECKED ? 1 : 0); break;
    case IdShowKeys: writeDword(L"ShowKeys", Button_GetCheck(showKeys_) == BST_CHECKED ? 1 : 0); break;
    default: return;
    }
    updateAll();
}

LRESULT CALLBACK App::trayProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
    }
    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    return app ? app->onTray(hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK App::floatingProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
    }
    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    return app ? app->onFloating(hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK App::optionsProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
    }
    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    return app ? app->onOptions(hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT App::onTray(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == taskbarCreatedMessage_ && taskbarCreatedMessage_ != 0) {
        installTrayIcon();
        updateTrayIcon();
        return 0;
    }
    switch (message) {
    case kTrayMessage:
        switch (LOWORD(lParam)) {
        case WM_CONTEXTMENU:
        case WM_RBUTTONUP: showTrayMenu(); return 0;
        case WM_LBUTTONUP: toggleMonitor(); return 0;
        case WM_LBUTTONDBLCLK: showOptions(); return 0;
        default: break;
        }
        return 0;
    case kRefreshCompleteMessage:
        onRefreshComplete(reinterpret_cast<RefreshResult*>(lParam));
        return 0;
    case WM_TIMER:
        if (wParam == kPollTimer) {
            KillTimer(hwnd, kPollTimer);
            refresh();
        } else if (wParam == kRefreshWatchdogTimer && !refreshing_) {
            // The refresh ended and its completion never arrived: the worker's
            // post failed. A posted message is always retrieved before a
            // WM_TIMER, so a completion that was posted has been handled (and
            // killed this timer) by now. Still refreshing: the timer is
            // periodic and looks again.
            KillTimer(hwnd, kRefreshWatchdogTimer);
            scheduleNextPoll(true);
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IdTrayShow: toggleMonitor(); return 0;
        case IdTrayRefresh:
            KillTimer(hwnd, kPollTimer);
            refresh();
            return 0;
        case IdTrayConsole: openConsole(); return 0;
        case IdTrayOptions: showOptions(); return 0;
        case IdTrayQuit: DestroyWindow(hwnd); return 0;
        default: break;
        }
        return 0;
    case WM_DESTROY: {
        KillTimer(hwnd, kPollTimer);
        KillTimer(hwnd, kRefreshWatchdogTimer);
        NOTIFYICONDATAW data{sizeof(data)};
        data.hWnd = hwnd;
        data.uID = 1;
        Shell_NotifyIconW(NIM_DELETE, &data);
        if (refreshThread_.joinable()) refreshThread_.join();
        if (trayIcon_) DestroyIcon(trayIcon_);
        if (font_) DeleteObject(font_);
        if (darkBrush_) DeleteObject(darkBrush_);
        if (editBrush_) DeleteObject(editBrush_);
        destroyMonitorBitmap();
        PostQuitMessage(0);
        return 0;
    }
    default: break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT App::onFloating(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        tooltip_ = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                   CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, nullptr, instance_, nullptr);
        TOOLINFOW info{sizeof(info)};
        info.uFlags = TTF_TRACK | TTF_ABSOLUTE;
        info.hwnd = hwnd;
        info.uId = 1;
        info.lpszText = const_cast<wchar_t*>(L"");
        SendMessageW(tooltip_, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
        SendMessageW(tooltip_, TTM_SETMAXTIPWIDTH, 0, 440);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: paintFloating(); return 0;
    case WM_SIZE: InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT) {
            POINT cursor{};
            GetCursorPos(&cursor);
            ScreenToClient(hwnd, &cursor);
            switch (resizeEdgeAt(cursor)) {
            case ResizeEdge::Right: SetCursor(LoadCursorW(nullptr, IDC_SIZEWE)); return TRUE;
            case ResizeEdge::Bottom: SetCursor(LoadCursorW(nullptr, IDC_SIZENS)); return TRUE;
            case ResizeEdge::Corner: SetCursor(LoadCursorW(nullptr, IDC_SIZENWSE)); return TRUE;
            case ResizeEdge::None: break;
            }
            if (const auto* hit = hitAt(cursor); hit && rows_[hit->row].kind == RowKind::Status && state_ != ConnectionState::Connected) {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
        }
        break;
    case WM_LBUTTONDOWN: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        GetCursorPos(&dragStart_);
        RECT rect{};
        GetWindowRect(hwnd, &rect);
        if (const auto edge = resizeEdgeAt(point); edge != ResizeEdge::None) {
            resizing_ = true;
            resizeEdge_ = edge;
            resizeCursorStart_ = dragStart_;
            resizeStartWidth_ = rect.right - rect.left;
        } else {
            dragging_ = true;
            windowStart_ = {rect.left, rect.top};
        }
        SetCapture(hwnd);
        return 0;
    }
    case WM_MOUSEMOVE: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        POINT cursor{};
        GetCursorPos(&cursor);
        const bool pastSlop = std::abs(static_cast<int>(cursor.x - dragStart_.x)) > kMonitorClickSlop
            || std::abs(static_cast<int>(cursor.y - dragStart_.y)) > kMonitorClickSlop;
        if (resizing_ && (wParam & MK_LBUTTON) && pastSlop) {
            // The widget keeps its aspect ratio, so vertical drags are mapped back onto width.
            const double aspect = static_cast<double>(logicalWidth_) / static_cast<double>(logicalHeight_);
            const int dx = static_cast<int>(cursor.x - resizeCursorStart_.x);
            const int dy = static_cast<int>(std::lround((cursor.y - resizeCursorStart_.y) * aspect));
            int delta = dx;
            if (resizeEdge_ == ResizeEdge::Bottom) delta = dy;
            else if (resizeEdge_ == ResizeEdge::Corner) delta = std::abs(dx) >= std::abs(dy) ? dx : dy;
            const int width = std::max(resizeStartWidth_ + delta, kMonitorMinWindowWidth);
            const int height = std::max(1, static_cast<int>(std::lround(static_cast<double>(logicalHeight_) * width / static_cast<double>(logicalWidth_))));
            SetWindowPos(hwnd, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            const int corner = std::max(4, static_cast<int>(std::lround(kMonitorCorner * monitorScale())));
            SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, width, height, corner, corner), TRUE);
        } else if (dragging_ && (wParam & MK_LBUTTON) && pastSlop) {
            SetWindowPos(hwnd, nullptr, windowStart_.x + cursor.x - dragStart_.x, windowStart_.y + cursor.y - dragStart_.y,
                         0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        } else if (!(wParam & MK_LBUTTON)) {
            activateTooltip(point);
            TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, hwnd, 0};
            TrackMouseEvent(&track);
        }
        return 0;
    }
    case WM_MOUSELEAVE: SendMessageW(tooltip_, TTM_TRACKACTIVATE, FALSE, 0); return 0;
    case WM_LBUTTONUP: {
        POINT cursor{};
        GetCursorPos(&cursor);
        const bool moved = std::abs(static_cast<int>(cursor.x - dragStart_.x)) > kMonitorClickSlop
            || std::abs(static_cast<int>(cursor.y - dragStart_.y)) > kMonitorClickSlop;
        const bool wasResizing = resizing_;
        dragging_ = false;
        resizing_ = false;
        ReleaseCapture();
        RECT rect{};
        GetWindowRect(hwnd, &rect);
        writeDword(L"MonitorX", static_cast<DWORD>(rect.left));
        writeDword(L"MonitorY", static_cast<DWORD>(rect.top));
        writeDword(L"MonitorWidth", static_cast<DWORD>(rect.right - rect.left));
        if (wasResizing && moved) {
            destroyMonitorBitmap();
            syncFloatingWindowSize();
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        if (!moved && !wasResizing) handleMonitorClick({GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)});
        return 0;
    }
    case WM_CAPTURECHANGED:
        dragging_ = false;
        resizing_ = false;
        return 0;
    case WM_LBUTTONDBLCLK: showOptions(); return 0;
    case WM_RBUTTONUP: showTrayMenu(); return 0;
    default: break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT App::onOptions(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_SIZE: layoutOptions(LOWORD(lParam), HIWORD(lParam)); return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
        info->ptMinTrackSize = {600, 520};
        return 0;
    }
    case WM_CLOSE:
        persistOptions();
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IdRefresh:
            persistOptions();
            KillTimer(trayWindow_, kPollTimer);
            refresh();
            return 0;
        case IdClearKey:
            deleteKey();
            SetWindowTextW(key_, L"");
            persistOptions();
            return 0;
        case IdOpenConsole: openConsole(); return 0;
        case IdClose: SendMessageW(hwnd, WM_CLOSE, 0, 0); return 0;
        case IdAlwaysOnTop:
        case IdLaunchAtLogin:
        case IdShowAllModels:
        case IdShowUsers:
        case IdShowKeys:
            if (HIWORD(wParam) == BN_CLICKED) applyCheckbox(LOWORD(wParam));
            return 0;
        default: break;
        }
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        SetBkColor(reinterpret_cast<HDC>(wParam), kBackground);
        SetTextColor(reinterpret_cast<HDC>(wParam), kText);
        return reinterpret_cast<LRESULT>(darkBrush_);
    case WM_CTLCOLOREDIT:
        SetBkColor(reinterpret_cast<HDC>(wParam), kEditBackground);
        SetTextColor(reinterpret_cast<HDC>(wParam), kText);
        return reinterpret_cast<LRESULT>(editBrush_);
    default: break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR commandLine, int) {
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\HypeLLMMonitor.SingleInstance");
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"HypeLLM Monitor is already running.", kAppName, MB_OK | MB_ICONINFORMATION);
        if (mutex) CloseHandle(mutex);
        return 0;
    }
    App app;
    if (!app.initialize(instance)) {
        MessageBoxW(nullptr, L"HypeLLM Monitor could not initialise its Windows interface.", kAppName, MB_OK | MB_ICONERROR);
        CloseHandle(mutex);
        return 1;
    }
    if (commandLine && wcsstr(commandLine, L"--options")) app.showOptionsWindow();
    const int result = app.run();
    CloseHandle(mutex);
    return result;
}
