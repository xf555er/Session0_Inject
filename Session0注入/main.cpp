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

//��ȡ����ID�ĺ���
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


//��Ȩ���������õ�����Ȩ
//�����������Ҫ���������õ�ǰ���̵ġ�debug programs����Ȩ�������Ȩ������̸��ӵ��������̲���������
BOOL EnableDebugPrivilege()
{	
	
	HANDLE hToken; // ���ڱ�����̷������Ƶľ��
	BOOL fOk = FALSE; // ���ڱ��溯���Ƿ�ִ�гɹ���״̬

	// ��ȡ��ǰ���̵ķ�������
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp; // ���ڱ�����Ȩ��Ϣ�Ľṹ��
		tp.PrivilegeCount = 1; // ������Ȩ����Ϊ1

		// ��ȡ��Debug Programs����Ȩ�ı���Ψһ��ʶ����LUID��
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // ������Ȩ������Ϊ����

		// �����������ƣ����á�Debug Programs����Ȩ
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS); // ����Ƿ�ɹ�������Ȩ
		CloseHandle(hToken); // �رշ������Ƶľ��
	}
	return fOk; // ���غ����Ƿ�ִ�гɹ���״̬
}


BOOL Session0Inject(DWORD pid, char* dllPath)
{	
	EnableDebugPrivilege();  //��Ȩ
	DWORD DllNameLength = strlen(dllPath);  //��ȡdll·�����ĳ���

	// ����ļ��Ƿ����  ע��:<filesystem>����ʹ��֧��C++17����߰汾�ı�����
	if (!std::filesystem::exists(dllPath)) {
		printf("ָ����DLL�ļ�������\n");
		return -1;
	}

	//1 ��ȡĿ�Ľ��̾��
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("�򿪽���ʧ��: %d\n", GetLastError());
		return -1;
	}

	//2 ΪĿ�Ľ��̷����ڴ�,���ڴ��Loadlibrary����Ĳ���,��dll��·��
	VOID* paraAddr = VirtualAllocEx(hProcess, NULL, DllNameLength + 1, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == paraAddr)
	{
		printf("�ڴ����ʧ��\n");
		return -1;
	}

	//3 ��DLL��·��д��Ŀ����̵��ڴ�
	if (!WriteProcessMemory(hProcess, paraAddr, dllPath, DllNameLength + 1, NULL))
	{
		printf("д���ڴ�ʧ�ܣ�\n");
		return false;
	}

	//4 ��ȡloadlibrary�����ĵ�ַ
	HMODULE LibHandle = GetModuleHandle("kernel32.dll");
	FARPROC ProcAdd = GetProcAddress(LibHandle, "LoadLibraryA");
	if (!ProcAdd)
	{
		printf("��ȡLoadLibraryAʧ��!\n");
		return false;
	}

	//5 ͨ������GetProcAddress��������ȡZwCreateThreadEx�����ĵ�ַ
	HMODULE hNtdllDll = LoadLibrary("ntdll.dll");
	DWORD dwStatus;
	HANDLE hRemoteThread; 
	Fn_ZwCreateThreadEx ZwCreateThreadEx = (Fn_ZwCreateThreadEx)GetProcAddress(hNtdllDll, "ZwCreateThreadEx");
	if (NULL == ZwCreateThreadEx)
	{
		printf("GetProcAddress error\n");
		return -1;
	}

	//6 ʹ�û�ȡ����ZwCreateThreadEx������Ŀ������д����̣߳�����LoadLibraryA����������ΪDLL·��
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)ProcAdd, paraAddr, 0, 0, 0, 0, NULL);
	if (NULL == ZwCreateThreadEx)
	{
		printf("ZwCreateThreadEx error\n");
		return -1;
	}

	//�ͷ�dll
	FreeLibrary(hNtdllDll);

	//�ͷž��
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
}


int main(int argc, char* argv[])
{
	if (argc == 3)
	{	
		//atoi�����ɽ��ַ���ת��Ϊ����
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
		printf("����������������,����1Ϊpid,����2Ϊdll�ľ���·��\n");
		exit(1);
	}
}