#include <windows.h>
#include <shlobj.h>
#include <shlobj_core.h>
#include <shobjidl.h>
#include <urlmon.h>
#include <tlhelp32.h>

#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Urlmon.lib")

namespace fs = std::filesystem;

namespace {
    const wchar_t* kAppExeName = L"ACS_Wynn_Builder.exe";
    const wchar_t* kRepositoryOwner = L"congiirepair";
    const wchar_t* kRepositoryName = L"ACS_Wynn_Builder";
    const wchar_t* kAssetName = L"ACS_Wynn_Builder_Update.zip";

    enum class UpdateChannel {
        Stable,
        Testing
    };

    class ScopedProgressDialog {
    public:
        ScopedProgressDialog() = default;

        ~ScopedProgressDialog() {
            if (dialog_) {
                dialog_->StopProgressDialog();
                dialog_->Release();
            }
        }

        bool start(const std::wstring& title, const std::wstring& stageLine) {
            HRESULT hr = CoCreateInstance(CLSID_ProgressDialog, nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(&dialog_));
            if (FAILED(hr) || !dialog_)
                return false;

            dialog_->SetTitle(title.c_str());
            dialog_->SetLine(1, stageLine.c_str(), FALSE, nullptr);
            dialog_->SetLine(2, L"Preparing update...", FALSE, nullptr);
            dialog_->StartProgressDialog(nullptr, nullptr, PROGDLG_AUTOTIME | PROGDLG_NOMINIMIZE, nullptr);
            dialog_->SetProgress64(0, 100);
            return true;
        }

        void setStage(const std::wstring& stageLine, ULONGLONG completedPercent) {
            if (!dialog_)
                return;
            dialog_->SetLine(1, stageLine.c_str(), FALSE, nullptr);
            dialog_->SetProgress64(completedPercent, 100);
            pump();
        }

        void setDetail(const std::wstring& detailLine) {
            if (!dialog_)
                return;
            dialog_->SetLine(2, detailLine.c_str(), FALSE, nullptr);
            pump();
        }

        void setProgress(ULONGLONG completedPercent) {
            if (!dialog_)
                return;
            dialog_->SetProgress64(completedPercent, 100);
            pump();
        }

    private:
        void pump() {
            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        IProgressDialog* dialog_ = nullptr;
    };

    std::wstring quote(const std::wstring& value) {
        return L"\"" + value + L"\"";
    }

    void showMessage(const std::wstring& text, const std::wstring& title, UINT type = MB_OK | MB_ICONINFORMATION) {
        MessageBoxW(nullptr, text.c_str(), title.c_str(), type);
    }

    std::wstring toLower(std::wstring value) {
        for (wchar_t& ch : value)
            ch = static_cast<wchar_t>(towlower(ch));
        return value;
    }

    std::optional<fs::path> browseForFolder() {
        IFileDialog* dialog = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&dialog));
        if (FAILED(hr))
            return std::nullopt;

        DWORD options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        dialog->SetTitle(L"Select the existing ACS Tool install folder");

        std::optional<fs::path> result;
        if (SUCCEEDED(dialog->Show(nullptr))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dialog->GetResult(&item))) {
                PWSTR rawPath = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &rawPath)) && rawPath) {
                    result = fs::path(rawPath);
                    CoTaskMemFree(rawPath);
                }
                item->Release();
            }
        }

        dialog->Release();
        return result;
    }

    std::optional<fs::path> selectTargetFolder() {
        return browseForFolder();
    }

    bool runHiddenProcess(const std::wstring& commandLine) {
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION processInfo{};
        std::wstring mutableCommand = commandLine;
        if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startupInfo, &processInfo)) {
            return false;
        }

        WaitForSingleObject(processInfo.hProcess, INFINITE);
        DWORD exitCode = 1;
        GetExitCodeProcess(processInfo.hProcess, &exitCode);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return exitCode == 0;
    }

    bool runHiddenProcessCapture(const std::wstring& commandLine, std::wstring& output) {
        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = TRUE;

        HANDLE readPipe = nullptr;
        HANDLE writePipe = nullptr;
        if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0))
            return false;

        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        startupInfo.wShowWindow = SW_HIDE;
        startupInfo.hStdOutput = writePipe;
        startupInfo.hStdError = writePipe;

        PROCESS_INFORMATION processInfo{};
        std::wstring mutableCommand = commandLine;
        const BOOL created = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startupInfo, &processInfo);
        CloseHandle(writePipe);

        if (!created) {
            CloseHandle(readPipe);
            return false;
        }

        std::string collected;
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
            collected.append(buffer, buffer + bytesRead);

        CloseHandle(readPipe);
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        DWORD exitCode = 1;
        GetExitCodeProcess(processInfo.hProcess, &exitCode);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);

        const int wideLength = MultiByteToWideChar(CP_UTF8, 0, collected.data(),
            static_cast<int>(collected.size()), nullptr, 0);
        if (wideLength > 0) {
            output.resize(static_cast<size_t>(wideLength));
            MultiByteToWideChar(CP_UTF8, 0, collected.data(), static_cast<int>(collected.size()),
                output.data(), wideLength);
        }
        else {
            output.assign(collected.begin(), collected.end());
        }

        return exitCode == 0;
    }

    bool extractArchive(const fs::path& zipPath, const fs::path& extractPath) {
        std::wstringstream command;
        command << L"powershell -NoProfile -ExecutionPolicy Bypass -Command "
                << quote(L"$ErrorActionPreference='Stop'; "
                         L"Expand-Archive -LiteralPath "
                         + quote(zipPath.native()) + L" -DestinationPath "
                         + quote(extractPath.native()) + L" -Force");
        return runHiddenProcess(command.str());
    }

    std::optional<fs::path> resolveSourceRoot(const fs::path& extractPath) {
        std::vector<fs::path> entries;
        for (const auto& entry : fs::directory_iterator(extractPath))
            entries.push_back(entry.path());

        if (entries.empty())
            return std::nullopt;

        if (entries.size() == 1 && fs::is_directory(entries.front()))
            return entries.front();

        return extractPath;
    }

    bool killMatchingProcesses(const fs::path& targetExe) {
        const std::wstring normalizedTarget = toLower(fs::weakly_canonical(targetExe).native());
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        BOOL hasEntry = Process32FirstW(snapshot, &entry);
        while (hasEntry) {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                FALSE, entry.th32ProcessID);
            if (process) {
                wchar_t processPath[MAX_PATH * 4] = {};
                DWORD size = static_cast<DWORD>(std::size(processPath));
                if (QueryFullProcessImageNameW(process, 0, processPath, &size)) {
                    if (toLower(processPath) == normalizedTarget) {
                        TerminateProcess(process, 0);
                        WaitForSingleObject(process, 5000);
                    }
                }
                CloseHandle(process);
            }
            hasEntry = Process32NextW(snapshot, &entry);
        }

        CloseHandle(snapshot);
        return true;
    }

    bool copyDirectoryContents(const fs::path& sourceRoot, const fs::path& targetRoot, std::wstring& failurePath,
        ScopedProgressDialog* progress = nullptr) {
        std::vector<fs::path> files;
        for (const auto& entry : fs::recursive_directory_iterator(sourceRoot)) {
            if (entry.is_regular_file())
                files.push_back(entry.path());
        }

        const ULONGLONG totalFiles = files.empty() ? 1 : static_cast<ULONGLONG>(files.size());
        ULONGLONG processedFiles = 0;

        for (const auto& entry : fs::recursive_directory_iterator(sourceRoot)) {
            const fs::path relative = fs::relative(entry.path(), sourceRoot);
            const fs::path destination = targetRoot / relative;

            std::error_code ec;
            if (entry.is_directory()) {
                fs::create_directories(destination, ec);
                if (ec) {
                    failurePath = destination.native();
                    return false;
                }
                continue;
            }

            fs::create_directories(destination.parent_path(), ec);
            if (ec) {
                failurePath = destination.parent_path().native();
                return false;
            }

            fs::copy_file(entry.path(), destination, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                failurePath = destination.native();
                return false;
            }

            ++processedFiles;
            if (progress) {
                const ULONGLONG fileProgress = 65 + ((processedFiles * 30) / totalFiles);
                progress->setStage(L"Replacing files in the selected ACS Tool folder...", fileProgress);
                progress->setDetail(L"Copying: " + destination.filename().native());
            }
        }

        return true;
    }

    bool launchTarget(const fs::path& exePath) {
        const HINSTANCE result = ShellExecuteW(nullptr, L"open", exePath.c_str(), nullptr,
            exePath.parent_path().c_str(), SW_SHOWNORMAL);
        return reinterpret_cast<INT_PTR>(result) > 32;
    }

    std::wstring trim(std::wstring value) {
        const auto first = value.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
            return L"";
        const auto last = value.find_last_not_of(L" \t\r\n");
        return value.substr(first, last - first + 1);
    }

    std::optional<std::pair<std::wstring, std::wstring>> resolveGithubDownload(UpdateChannel channel) {
        std::wstringstream script;
        script << L"$ProgressPreference='SilentlyContinue';"
               << L"$repo='https://api.github.com/repos/" << kRepositoryOwner << L"/" << kRepositoryName << L"';";
        if (channel == UpdateChannel::Testing)
            script << L"$release=Invoke-RestMethod -UseBasicParsing -Uri ($repo + '/releases') | Where-Object { -not $_.draft -and $_.prerelease } | Select-Object -First 1;";
        else
            script << L"$release=Invoke-RestMethod -UseBasicParsing -Uri ($repo + '/releases/latest');";
        script << L"if(-not $release){exit 3};"
               << L"$tag=[string]$release.tag_name;"
               << L"if($tag.StartsWith('v')){$tag=$tag.Substring(1)};"
               << L"$asset=$release.assets | Where-Object { $_.name -eq '" << kAssetName << L"' } | Select-Object -First 1;"
               << L"if(-not $asset){$asset=$release.assets | Where-Object { $_.name -match '\\.(zip|exe)$' } | Select-Object -First 1};"
               << L"if(-not $asset){exit 4};"
               << L"[Console]::WriteLine($tag);"
               << L"[Console]::Write([string]$asset.browser_download_url);";

        std::wstringstream command;
        command << L"powershell -NoProfile -ExecutionPolicy Bypass -Command " << quote(script.str());

        std::wstring output;
        if (!runHiddenProcessCapture(command.str(), output))
            return std::nullopt;

        const auto newline = output.find_first_of(L"\r\n");
        if (newline == std::wstring::npos)
            return std::nullopt;

        const std::wstring version = trim(output.substr(0, newline));
        const std::wstring url = trim(output.substr(output.find_first_not_of(L"\r\n", newline)));
        if (version.empty() || url.empty())
            return std::nullopt;

        return std::make_pair(version, url);
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    const auto targetFolder = selectTargetFolder();
    if (!targetFolder) {
        CoUninitialize();
        return 0;
    }

    const fs::path targetExe = *targetFolder / kAppExeName;
    if (!fs::exists(targetExe)) {
        showMessage(L"The selected folder does not contain ACS_Wynn_Builder.exe.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    const int ready = MessageBoxW(nullptr,
        (L"The recovery tool will:\n\n"
         L"1. Close ACS Tool if it is running\n"
         L"2. Download the selected ACS_Wynn_Builder_Update.zip from GitHub\n"
         L"3. Replace the files in your existing install folder\n"
         L"4. Relaunch ACS Tool\n\n"
         L"Continue?"),
        L"ACS Recovery Tool", MB_OKCANCEL | MB_ICONQUESTION);
    if (ready != IDOK) {
        CoUninitialize();
        return 0;
    }

    const int channelChoice = MessageBoxW(nullptr,
        L"Choose which GitHub channel to recover from.\n\n"
        L"Yes = Stable release\n"
        L"No = Testing build\n"
        L"Cancel = Stop",
        L"ACS Recovery Tool",
        MB_YESNOCANCEL | MB_ICONQUESTION);
    if (channelChoice == IDCANCEL) {
        CoUninitialize();
        return 0;
    }

    const UpdateChannel channel = channelChoice == IDNO ? UpdateChannel::Testing : UpdateChannel::Stable;
    const auto downloadInfo = resolveGithubDownload(channel);
    if (!downloadInfo) {
        showMessage(L"The recovery tool could not resolve the selected GitHub build.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    const fs::path tempRoot = fs::temp_directory_path() / L"ACS_Recovery_Tool";
    const fs::path zipPath = tempRoot / kAssetName;
    const fs::path extractPath = tempRoot / L"extract";
    ScopedProgressDialog progress;
    progress.start(L"ACS Recovery Tool", L"Preparing update...");

    std::error_code ec;
    fs::remove_all(tempRoot, ec);
    fs::create_directories(tempRoot, ec);
    if (ec) {
        showMessage(L"The recovery tool could not prepare its temporary working folder.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    const std::wstring channelLabel = channel == UpdateChannel::Testing ? L"testing build" : L"stable release";
    progress.setStage(L"Downloading the selected recovery package from GitHub...", 10);
    progress.setDetail(L"Downloading " + std::wstring(kAssetName) + L" (" + channelLabel + L")");
    if (FAILED(URLDownloadToFileW(nullptr, downloadInfo->second.c_str(), zipPath.c_str(), 0, nullptr))) {
        showMessage(L"The recovery tool could not download the selected package from GitHub.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    killMatchingProcesses(targetExe);

    progress.setStage(L"Extracting the downloaded update package...", 45);
    progress.setDetail(L"Unpacking files");
    if (!extractArchive(zipPath, extractPath)) {
        showMessage(L"The recovery tool could not extract the downloaded package.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    const auto sourceRoot = resolveSourceRoot(extractPath);
    if (!sourceRoot) {
        showMessage(L"The downloaded package was empty or invalid.",
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    std::wstring failurePath;
    progress.setStage(L"Replacing files in the selected ACS Tool folder...", 65);
    progress.setDetail(L"Copying updated files");
    if (!copyDirectoryContents(*sourceRoot, *targetFolder, failurePath, &progress)) {
        showMessage(L"The recovery tool could not replace all files.\n\nFailed at:\n" + failurePath,
            L"ACS Recovery Tool", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    progress.setStage(L"Relaunching ACS Tool...", 98);
    progress.setDetail(L"Starting ACS_Wynn_Builder.exe");
    if (!launchTarget(targetExe)) {
        showMessage(L"The update was applied, but the app could not be relaunched automatically.\n\n"
                    L"Please open ACS_Wynn_Builder.exe manually from your existing install folder.",
            L"ACS Recovery Tool", MB_OK | MB_ICONWARNING);
        CoUninitialize();
        return 0;
    }

    progress.setStage(L"Update complete.", 100);
    progress.setDetail(L"ACS Tool was updated successfully to " + downloadInfo->first + L".");
    showMessage(L"ACS Tool was updated successfully from the " + channelLabel + L" channel and relaunched.",
        L"ACS Recovery Tool");
    CoUninitialize();
    return 0;
}
