#include <iostream>
#include <map>
#include <windows.h>
#include <powrprof.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "PowrProf.lib")

bool enable_shutdown_privilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		std::cerr << "OpenProcessToken failed: " << GetLastError() << '\n';
		return false;
	}

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, 0);

	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << '\n';
		return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || argv[1] == "help")
	{
		std::cout << "Usage: " << argv[0] << " <command>\n";

		std::cout << "Commands:\n";
		std::cout << "  shutdown\n";
		std::cout << "  reboot\n";
		std::cout << "  lock\n";
		std::cout << "  sleep\n";
		std::cout << "  sleep-de (sleep with wakeup events disabled)\n";
		std::cout << "  hibernate\n";
		return 0;
	}

	if (!enable_shutdown_privilege())
	{
		std::cerr << "Failed to enable shutdown privilege\n";
		return 1;
	}

	std::map<std::string, void(*)()> commands;
	commands.insert(std::make_pair("shutdown", []()
	{
		auto result = ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF, 0);
		if (result) std::cout << "Shutdown initiated\n";
		else std::cerr << "Failed to initiate shutdown: " << GetLastError() << '\n';
	}));
	commands.insert(std::make_pair("reboot", []()
	{
		auto result = ExitWindowsEx(EWX_REBOOT, 0);
		if (result) std::cout << "Reboot initiated\n";
		else std::cerr << "Failed to initiate reboot: " << GetLastError() << '\n';
	}));
	commands.insert(std::make_pair("lock", []()
	{
		auto result = LockWorkStation();
		if (result) std::cout << "Workstation locked\n";
		else std::cerr << "Failed to lock workstation: " << GetLastError() << '\n';
	}));
	commands.insert(std::make_pair("sleep", []()
	{
		auto result = SetSuspendState(FALSE, FALSE, FALSE);
		if (result) std::cout << "Sleep initiated\n";
		else std::cerr << "Failed to initiate sleep: " << GetLastError() << '\n';
	}));
	commands.insert(std::make_pair("sleep-de", []()
	{
		auto result = SetSuspendState(FALSE, FALSE, TRUE);
		if (result) std::cout << "Sleep (with wakeup events disabled) initiated\n";
		else std::cerr << "Failed to initiate sleep (with wakeup events disabled): " << GetLastError() << '\n';
	}));
	commands.insert(std::make_pair("hibernate", []()
	{
		auto result = SetSuspendState(TRUE, FALSE, FALSE);
		if (result) std::cout << "Hibernate initiated\n";
		else std::cerr << "Failed to initiate hibernate: " << GetLastError() << '\n';
	}));

	auto it = commands.find(argv[1]);
    if (it != commands.end())
        it->second();
    else
		std::cerr << "Unknown command: " << argv[1] << '\n';

	return 0;
}
