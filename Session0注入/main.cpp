#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <filesystem>

#ifdef _WIN64
typedef DWORD(WINAPI* Fn_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* Fn_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif

//获取进程ID的函数
DWORD GetProcessIdByName(const std::wstring& name) {
	DWORD pid = 0;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W entry = { sizeof(entry) };
		if (Process32FirstW(snap, &entry)) {
			do {
				if (std::wstring(entry.szExeFile) == name) {
					pid = entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snap, &entry));
		}
		CloseHandle(snap);
	}
	return pid;
}


//提权函数，启用调试特权
//这个函数的主要作用是启用当前进程的“debug programs”特权，这个特权允许进程附加到其他进程并控制它们
BOOL EnableDebugPrivilege()
{	
	
	HANDLE hToken; // 用于保存进程访问令牌的句柄
	BOOL fOk = FALSE; // 用于保存函数是否执行成功的状态

	// 获取当前进程的访问令牌
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp; // 用于保存特权信息的结构体
		tp.PrivilegeCount = 1; // 设置特权数量为1

		// 获取“Debug Programs”特权的本地唯一标识符（LUID）
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // 设置特权的属性为启用

		// 调整访问令牌，启用“Debug Programs”特权
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS); // 检查是否成功启用特权
		CloseHandle(hToken); // 关闭访问令牌的句柄
	}
	return fOk; // 返回函数是否执行成功的状态
}


BOOL Session0Inject(DWORD pid, char* dllPath)
{	
	EnableDebugPrivilege();  //提权
	DWORD DllNameLength = strlen(dllPath);  //获取dll路径名的长度

	// 检查文件是否存在  注意:<filesystem>库需使用支持C++17或更高版本的编译器
	if (!std::filesystem::exists(dllPath)) {
		printf("指定的DLL文件不存在\n");
		return -1;
	}

	//1 获取目的进程句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("打开进程失败: %d\n", GetLastError());
		return -1;
	}

	//2 为目的进程分配内存,用于存放Loadlibrary传入的参数,即dll的路径
	VOID* paraAddr = VirtualAllocEx(hProcess, NULL, DllNameLength + 1, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == paraAddr)
	{
		printf("内存分配失败\n");
		return -1;
	}

	//3 将DLL的路径写到目标进程的内存
	if (!WriteProcessMemory(hProcess, paraAddr, dllPath, DllNameLength + 1, NULL))
	{
		printf("写入内存失败！\n");
		return false;
	}

	//4 获取loadlibrary函数的地址
	HMODULE LibHandle = GetModuleHandle("kernel32.dll");
	FARPROC ProcAdd = GetProcAddress(LibHandle, "LoadLibraryA");
	if (!ProcAdd)
	{
		printf("获取LoadLibraryA失败!\n");
		return false;
	}

	//5 通过调用GetProcAddress函数来获取ZwCreateThreadEx函数的地址
	HMODULE hNtdllDll = LoadLibrary("ntdll.dll");
	DWORD dwStatus;
	HANDLE hRemoteThread; 
	Fn_ZwCreateThreadEx ZwCreateThreadEx = (Fn_ZwCreateThreadEx)GetProcAddress(hNtdllDll, "ZwCreateThreadEx");
	if (NULL == ZwCreateThreadEx)
	{
		printf("GetProcAddress error\n");
		return -1;
	}

	//6 使用获取到的ZwCreateThreadEx函数在目标进程中创建线程，运行LoadLibraryA函数，参数为DLL路径
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)ProcAdd, paraAddr, 0, 0, 0, 0, NULL);
	if (NULL == ZwCreateThreadEx)
	{
		printf("ZwCreateThreadEx error\n");
		return -1;
	}

	//释放dll
	FreeLibrary(hNtdllDll);

	//释放句柄
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
}


int main(int argc, char* argv[])
{
	if (argc == 3)
	{	
		//atoi函数可将字符串转化为整数
		BOOL bRet = Session0Inject((DWORD)atoi(argv[1]), argv[2]);
		
		if (-1 == bRet)
		{
			printf("Inject dll failed\n");
		}
		else
		{
			printf("Inject dll successfully\n");
		}
	}
	else
	{
		printf("你需输入两个参数,参数1为pid,参数2为dll的绝对路径\n");
		exit(1);
	}
}