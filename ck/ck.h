#pragma once

#pragma warning(push, 3)

#define NTDDI_VERSION (0x0A000000) // Windows 10 1507 "Threshold"
#define _WIN32_WINNT (0x0A00)
#define WINVER (0x0A00)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
//#include <winternl.h>
#include <process.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <assert.h>

#include <ole2.h>
#include <olectl.h>
#include <tchar.h>

#include <dwmapi.h>
#include <d3d11.h>

#include <stdint.h>
#include <stdio.h>
#include <math.h>

#include <stdexcept>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <algorithm>

#include <atomic>
#include <mutex>
#include <thread>

#pragma warning(pop)

//
// BASIC
//

#define CK_TRACE_INFO ck_printf
#define CK_TRACE_ERROR ck_printf
#define CK_OutputDebugStringA OutputDebugStringA

#define CK_ASSERT(Cond) if (!(Cond)) { CK_TRACE_ERROR("FAIL at FILE:%s LINE:%d", __FILE__, __LINE__); /*__debugbreak();*/ }
#define CK_GUARD_RET(Cond, RetValue) if (!(Cond)) { CK_ASSERT(false); return (RetValue); }
#define CK_GUARD_BRK(Cond) if (!(Cond)) { CK_ASSERT(false); break; }

#define CK_INVALID_PID (DWORD)-1

inline void ck_printf(const char* Format, ...)
{
	char Buf[1024] = {0};
	va_list Args;
	va_start(Args, Format);
	const int Count = vsnprintf_s(Buf, _countof(Buf) - 1, _TRUNCATE, Format, Args);
	va_end(Args);
	OutputDebugStringA(Buf);
}

//
// HANDLE
//

template<typename T>
inline void SafeDelete(T*& Ptr) { if (Ptr) { delete Ptr; Ptr = NULL; } }

template<typename T>
inline void SafeReleaseCom(T*& Ptr) { if (Ptr) { Ptr->Release(); Ptr = NULL; } }

inline bool IsHandleValid(PVOID Handle) { return (Handle != NULL && Handle != INVALID_HANDLE_VALUE); }

template<typename T, typename Traits>
class TScopedHandle
{
public:
	T Handle;

	inline TScopedHandle() : Handle(NULL) {}
	inline explicit TScopedHandle(T h) : Handle(h) {}
	inline TScopedHandle(TScopedHandle& other) { Handle = other.Handle; other.Handle = NULL; }

	inline ~TScopedHandle() { Close(); }
	inline void Close() { Traits::Close(Handle); }

	inline T& operator*() { return Handle; }
	inline T* operator&() { return &Handle; }

	inline const T& operator*() const { return Handle; }
	inline const T* operator&() const { return &Handle; }

	inline T& operator->() { return Handle; }

	inline TScopedHandle& operator=(T h) { Close(); Handle = h; return *this; }
	inline TScopedHandle& operator=(TScopedHandle& other) { Close(); Handle = other.Handle; other.Handle = NULL; return *this; }

	inline operator bool() const { return IsHandleValid(Handle); }
};

struct HANDLE_traits { static void Close(HANDLE& Value) { if (IsHandleValid(Value)) { ::CloseHandle(Value); Value = NULL; } } };
struct HKEY_traits { static void Close(HKEY& Value) { if (IsHandleValid(Value)) { ::RegCloseKey(Value); Value = NULL; } } };
struct SC_HANDLE_traits { static void Close(SC_HANDLE& Value) { if (IsHandleValid(Value)) { ::CloseServiceHandle(Value); Value = NULL; } } };
struct COM_traits { template<typename T> static void Close(T*& Value) { if (Value) { Value->Release(); Value = NULL; } } };

typedef TScopedHandle<HANDLE, HANDLE_traits> CkScopedHandle;
typedef TScopedHandle<HKEY, HKEY_traits> CkScopedRegKey;
typedef TScopedHandle<SC_HANDLE, SC_HANDLE_traits> CkScopedServiceHandle;

//
// STRING
//

inline const char* operator* (const std::string& s) { return s.c_str(); }
inline const wchar_t* operator* (const std::wstring& s) { return s.c_str(); }

inline bool ck_strw(const std::string& s, std::wstring& out)
{
	out.clear();
	const auto slen = s.length(); CK_GUARD_RET(slen > 0, false);
	int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)slen, NULL, 0); CK_GUARD_RET(n > 0, false);
	out.resize(n, 0);
	n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)slen, &out[0], n); CK_GUARD_RET(n > 0, false);
	return true;
}

inline bool ck_stra(const std::wstring& s, std::string& out)
{
	out.clear();
	const auto slen = s.length(); CK_GUARD_RET(slen > 0, false);
	int n = WideCharToMultiByte(CP_ACP, 0, s.c_str(), (int)slen, 0, 0, 0, 0); CK_GUARD_RET(n > 0, false);
	out.resize(n, 0);
	n = WideCharToMultiByte(CP_ACP, 0, s.c_str(), (int)slen, &out[0], n, 0, 0); CK_GUARD_RET(n > 0, false);
	return true;
}

inline std::wstring ck_strw(const std::string& s)
{
	std::wstring r;
	ck_strw(s, r);
	return r;
}

inline std::string ck_stra(const std::wstring& s)
{
	std::string r;
	ck_stra(s, r);
	return r;
}

//
// COMMON
//

inline std::wstring CkExtractFileName(LPCWSTR Path)
{
	std::wstring Res;
	const int Len = (int)wcslen(Path);
	for (int i = Len - 1; i > 0; --i)
	{
		if (Path[i] == L'\\' || Path[i] == L'/')
		{
			Res.assign(Path + i + 1);
			break;
		}
	}
	return Res;
}

inline std::wstring CkExtractFilePath(LPCWSTR Path)
{
	std::wstring Res;
	const int Len = (int)wcslen(Path);
	for (int i = Len - 1; i > 0; --i)
	{
		if (Path[i] == L'\\' || Path[i] == L'/')
		{
			Res.assign(Path, i + 1);
			break;
		}
	}
	return Res;
}

inline std::wstring CkGetModulePath(HMODULE Module)
{
	CK_GUARD_RET(Module, L"");

	wchar_t Buffer[MAX_PATH];
	CK_GUARD_RET(GetModuleFileNameW(Module, Buffer, _countof(Buffer) - 1), L"");

	return CkExtractFilePath(Buffer);
}

inline DWORD CkGetPidByName(LPCWSTR ProcName)
{
	DWORD Pid = CK_INVALID_PID;

	CK_GUARD_RET(ProcName, Pid);

	CkScopedHandle Snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	CK_GUARD_RET(Snapshot, Pid);

	PROCESSENTRY32W Entry;
	ZeroMemory(&Entry, sizeof(Entry));
	Entry.dwSize = sizeof(Entry);

	if (Process32FirstW(Snapshot.Handle, &Entry))
	{
		do
		{
			if (_wcsicmp(Entry.szExeFile, ProcName) == 0)
			{
				Pid = Entry.th32ProcessID;
				break;
			}
		}
		while (Process32NextW(Snapshot.Handle, &Entry));
	}

	return Pid;
}

inline BOOL CkAdjustPrivilege(LPCSTR PrivilegeName, BOOL Enable)
{
	CK_GUARD_RET(PrivilegeName, FALSE);

	TOKEN_PRIVILEGES Privilege;
	ZeroMemory(&Privilege, sizeof(Privilege));
	Privilege.PrivilegeCount = 1;
	Privilege.Privileges[0].Attributes = (Enable ? SE_PRIVILEGE_ENABLED : 0);

	std::wstring NameW(ck_strw(PrivilegeName));
	CK_GUARD_RET(LookupPrivilegeValueW(NULL, *NameW, &Privilege.Privileges[0].Luid), FALSE);

	CkScopedHandle Token;
	CK_GUARD_RET(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token), FALSE);

	CK_GUARD_RET(AdjustTokenPrivileges(*Token, FALSE, &Privilege, sizeof(Privilege), NULL, NULL), FALSE);

	return TRUE;
}

//
// PATTERN
//

inline uint8_t CkParseHex(uint8_t Val)
{
	if (Val >= '0' && Val <= '9') return (Val - '0');
	if (Val >= 'a' && Val <= 'f') return (Val - 'a') + 10;
	if (Val >= 'A' && Val <= 'F') return (Val - 'A') + 10;
	return 0;
}

inline uint8_t CkParseByte(const char* Str)
{
	uint8_t hi = CkParseHex((uint8_t)Str[0]);
	uint8_t lo = CkParseHex((uint8_t)Str[1]);
	return ((hi << 4) | lo);
}

inline std::vector<uint8_t> CkParseByteArray(const char* Str)
{
	std::vector<uint8_t> Result;
	if (Str)
	{
		const size_t Len = strlen(Str);
		if (Len)
		{
			std::vector<uint8_t> Tmp;
			Tmp.reserve(Len);

			for (size_t i = 0; i < Len; i++)
			{
				if (isalnum(Str[i]))
					Tmp.push_back(Str[i]);
			}

			const size_t NumBytes = Tmp.size() / 2;
			if (NumBytes)
			{
				Result.resize(NumBytes);
				for (size_t i = 0; i < NumBytes; i++)
				{
					uint8_t hi = CkParseHex(Tmp[i*2]);
					uint8_t lo = CkParseHex(Tmp[(i*2)+1]);
					Result[i] = ((hi << 4) | lo);
				}
			}
		}
	}
	return Result;
}

template<const uint8_t Wildcard>
struct CkWildcard
{
	inline bool operator()(const uint8_t &a, const uint8_t &b) const
	{
		return (a == b || b == Wildcard);
	}
};

typedef CkWildcard<0xCC> CkWildcardCC; // Interrupt Type 3
typedef CkWildcard<0xCE> CkWildcardCE; // Interrupt if Overflow

#define CK_PAGE_EXECUTE_RWC (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

template<typename TCompare>
inline std::vector<uint8_t*> CkFindPatternIntern(const std::vector<uint8_t>& Pattern, size_t Limit)
{
	std::vector<uint8_t*> Result;

	SYSTEM_INFO SysInfo;
	ZeroMemory(&SysInfo, sizeof(SysInfo));
	GetSystemInfo(&SysInfo);

	uint8_t* MaxAddress = (uint8_t*)SysInfo.lpMaximumApplicationAddress;
	uint8_t* Ptr = (uint8_t*)SysInfo.lpMinimumApplicationAddress;

	HANDLE Process = GetCurrentProcess();
	TCompare Compare;

	while (Ptr < MaxAddress)
	{
		MEMORY_BASIC_INFORMATION MemInfo;
		if (!VirtualQueryEx(Process, Ptr, &MemInfo, sizeof(MemInfo)))
		{
			CK_TRACE_ERROR("VirtualQueryEx failed at %p (Err=0x%X)", Ptr, GetLastError());
			break;
		}

		if ((MemInfo.Protect & CK_PAGE_EXECUTE_RWC) && ((MemInfo.Protect & PAGE_GUARD) == 0) && ((MemInfo.Protect & PAGE_NOACCESS) == 0))
		{
			uint8_t* RegionPos = (uint8_t*)MemInfo.BaseAddress;
			uint8_t* RegionEnd = RegionPos + MemInfo.RegionSize;

			//CK_TRACE_INFO("Scan %p .. %p (0x%X)", RegionPos, RegionEnd, (UINT)MemInfo.RegionSize);

			while ((RegionPos = std::search(RegionPos, RegionEnd, Pattern.begin(), Pattern.end(), Compare)) != RegionEnd)
			{
				//CK_TRACE_INFO("Found pattern at %p", RegionPos);

				Result.push_back(RegionPos);

				if (Limit && Result.size() >= Limit)
					return Result;

				RegionPos++;
			}
		}

		Ptr += MemInfo.RegionSize;
	}

	return Result;
}

inline BOOL CkProtectWriteMemory(HANDLE Process, const std::vector<uint8_t>& Data, PVOID Addr, SIZE_T Offset)
{
	DWORD Prot = 0;
	CK_GUARD_RET(VirtualProtectEx(Process, Addr, Data.size(), PAGE_EXECUTE_READWRITE, &Prot), FALSE);

	//SIZE_T IoSize = 0;
	//CK_GUARD_RET(WriteProcessMemory(Process, (PVOID)((UINT64)Addr + (UINT64)Offset), &PatchBytes[0], PatchBytes.size(), &IoSize), FALSE);

	memcpy((PVOID)((UINT64)Addr + (UINT64)Offset), &Data[0], Data.size());

	DWORD Prot2 = 0;
	VirtualProtectEx(Process, Addr, Data.size(), Prot, &Prot2);

	return TRUE;
}
