#include "ck/ck.h"
#include "ck/dwm_hook.h"
#include "ck/dwm_overlay.h"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/Detour/x64Detour.hpp"

static volatile int _StopFlag = false;
static UINT32 CHwFullScreenRenderTarget_SwapChainBase_Offset = 0;
static UINT32 _CDWMSwapChain_DxgiSwapChain_Offset = 0;
static ID3D11Device* _Device = NULL;
static unsigned int _PresentId = 0;

//===============================================================================================//

#define DECL_HOOK(Name)\
	static LPVOID Name##_Loc = NULL;\
	static uint64_t Name##_Orig = 0;

#define ORIG_FUNC(Name) ((Name##_Proto)Name##_Orig)

#define SCOPED_HOOK(Dis, Name) ScopedDetour Hook_##Name(Dis, #Name, Name##_Loc, &Name##_Hook, &Name##_Orig)

struct ScopedDetour
{
	PLH::x64Detour Detour;
	void* LocAddr;
	bool Hooked;

	inline ScopedDetour(PLH::CapstoneDisassembler& Dis, const char* Name, void* Loc, void* Hook, uint64_t* Orig) :
		Detour((char*)Loc, (char*)Hook, Orig, Dis),
		LocAddr(Loc)
	{ 
		CK_TRACE_INFO("HOOK %p %s", Loc, Name);
		Hooked = Detour.hook();
		CK_TRACE_INFO("HOOK %p -> %s", Loc, (Hooked ? "OK" : "FAIL"));
	}

	inline ~ScopedDetour()
	{ 
		if (Hooked)
		{
			CK_TRACE_INFO("UNHOOK %p", LocAddr);
			Detour.unHook();
			Hooked = false;
		}
	}
};

//===============================================================================================//

static bool Find_SwapChain_Offset()
{
	/*
	__int64 __fastcall CDWMSwapChain::GetFrameStatisticsInternal(CDWMSwapChain *this, struct DXGI_FRAME_STATISTICS_DWM *a2)
	{
	  v2 = (*(__int64 (__fastcall **)(_QWORD, struct DXGI_FRAME_STATISTICS_DWM *))(**((_QWORD **)this + 53) + 160i64))(
			 *((_QWORD *)this + 53),
			 a2);
	}
	*/
	auto Pattern = CkParseByteArray(
		"40 53" // push    rbx
		"48 83 EC 30" // sub     rsp, 30h
		"48 8B 89 A8 01 00 00" // mov     rcx, [rcx+1A8h] // <-- OFFSET: ((_QWORD *)this + 53) = 53*8 = 1A8
		"48 8B 01" // mov     rax, [rcx]
		"48 8B 80 A0 00 00 00" // mov     rax, [rax+0A0h]
		"FF 15 CC CC CC CC" // call    cs:__guard_dispatch_icall_fptr
		"89 44 24 40" // mov     [rsp+38h+arg_0], eax
		"8B D8" // mov     ebx, eax
		"85 C0" // test    eax, eax
		"0F 88 CC CC CC CC" // js      loc_1800FC382
		"4C 8D 44 24 40" // lea     r8, [rsp+38h+arg_0]
		"33 D2" // xor     edx, edx
		"8B CB" // mov     ecx, ebx
		"E8 CC CC CC CC" // call    ?TranslateDXGIorD3DErrorInContext@@YA_NJW4Enum@DXGIFunctionContext@@PEAJ@Z ; TranslateDXGIorD3DErrorInContext(long,DXGIFunctionContext::Enum,long *)
		"8B 44 24 40" // mov     eax, [rsp+38h+arg_0]
		"48 83 C4 30" // add     rsp, 30h
		"5B" // pop     rbx
		"C3" // retn
	);

	auto Loc = CkFindPatternIntern<CkWildcardCC>(Pattern, 0);
	CK_GUARD_RET(Loc.size() == 1, false);

	CK_TRACE_INFO("FOUND: CDWMSwapChain_GetFrameStatisticsInternal=%p", Loc[0]);

	auto Offset = *(UINT32*)(Loc[0] + 9);
	CK_TRACE_INFO("FOUND: SwapChainOffset=0x%X", (UINT)Offset);
	CK_GUARD_RET(Offset, false);
	_CDWMSwapChain_DxgiSwapChain_Offset = Offset;

	return true;
}

//===============================================================================================//

typedef __int64 (_fastcall *CHwFullScreenRenderTarget_Present_Proto)(class CHwFullScreenRenderTarget* pThis, __int64 a2, char a3, const struct RenderTargetPresentParameters* a4);

DECL_HOOK(CHwFullScreenRenderTarget_Present)

static bool Find_CHwFullScreenRenderTarget_Present()
{
	// TODO: fix this idiotism in a smart way :D
	auto Pattern = CkParseByteArray(
		"48 89 5C 24 10" // mov     [rsp-38h+arg_8], rbx
		"4C 89 4C 24 20" // mov     [rsp-38h+arg_18], r9
		"55" // push    rbp
		"56" // push    rsi
		"57" // push    rdi
		"41 54" // push    r12
		"41 55" // push    r13
		"41 56" // push    r14
		"41 57" // push    r15
		"48 8B EC" // mov     rbp, rsp
		"48 83 EC 50" // sub     rsp, 50h
		"48 8D B9 70 FF FF FF" // lea     rdi, [rcx-90h]
		"45 8A F0" // mov     r14b, r8b
		"48 8B 07" // mov     rax, [rdi]
		"4C 8D 4D EC" // lea     r9, [rbp+var_14]
		"48 8B F1" // mov     rsi, rcx
		"4C 8D 45 E0" // lea     r8, [rbp+var_20]
		"45 33 E4" // xor     r12d, r12d
		"48 8B CF" // mov     rcx, rdi
		"8A DA" // mov     bl, dl
		"45 8B EC" // mov     r13d, r12d
		"48 8B 80 10 01 00 00" // mov     rax, [rax+110h]
		"FF 15 CC CC CC CC" // call    cs:__guard_dispatch_icall_fptr
		"85 C0" // test    eax, eax
		"78 33" // js      short loc_180045DD3
		"44 38 65 E0" // cmp     [rbp+var_20], r12b
		"74 2D" // jz      short loc_180045DD3
		"F6 45 EC 02" // test    [rbp+var_14], 2
		"75 27" // jnz     short loc_180045DD3
		"44 38 A6 63 01 00 00" // cmp     [rsi+163h], r12b
		"75 1E" // jnz     short loc_180045DD3
		"48 8B 06" // mov     rax, [rsi]
		"48 8B CE" // mov     rcx, rsi
		"48 8B 80 F8 00 00 00" // mov     rax, [rax+0F8h]
		"FF 15 CC CC CC CC" // call    cs:__guard_dispatch_icall_fptr
		"44 8B E8" // mov     r13d, eax
		"85 C0" // test    eax, eax
		"0F 88 CC CC CC CC" // js      loc_18010731E
		"48 8B 0F" // mov     rcx, [rdi]
		"4C 8D 4D E4" // lea     r9, [rbp+var_1C]
		"4C 8D 45 40" // lea     r8, [rbp+arg_0]
		"44 88 65 40" // mov     [rbp+arg_0], r12b
		"8A D3" // mov     dl, bl
		"44 89 65 E4" // mov     [rbp+var_1C], r12d
		"48 8B 81 10 01 00 00" // mov     rax, [rcx+110h]
		"48 8B CF" // mov     rcx, rdi
		"FF 15 CC CC CC CC" // call    cs:__guard_dispatch_icall_fptr
		"8B D8" // mov     ebx, eax
		"41 BF 01 00 00 00" // mov     r15d, 1
		"85 C0" // test    eax, eax
		"0F 88 CC CC CC CC" // js      loc_180107630
		"8B 45 E4" // mov     eax, [rbp+var_1C]
		"45 84 F6" // test    r14b, r14b
		"0F 85 CC CC CC CC" // jnz     loc_18010733E
		"89 45 E8" // mov     [rbp+var_18], eax
		"44 38 65 40" // cmp     [rbp+arg_0], r12b
		"0F 84 CC CC CC CC" // jz      loc_180045FB1
		"8B 46 78" // mov     eax, [rsi+78h]
		"48 8D BE 80 00 00 00" // lea     rdi, [rsi+80h]
		"4C 8B 76 08" // mov     r14, [rsi+8]
		"4C 8B 66 20" // mov     r12, [rsi+20h] // ### struct CSwapChainBase* v20 = (_DWORD *)*((_QWORD *)pThis + 4)
		"89 45 F0" // mov     [rbp+var_10], eax
		"33 C0" // xor     eax, eax
		"41 8B 9E 70 03 00 00" // mov     ebx, [r14+370h]
		"85 DB" // test    ebx, ebx
		"0F 88 CC CC CC CC" // js      loc_18010740D
		"38 05 CC CC CC CC" // cmp     cs:?g_fForceDeviceLost@@3_NA, al ; bool g_fForceDeviceLost
		"0F 85 CC CC CC CC" // jnz     loc_18010734A
	);

	auto Loc = CkFindPatternIntern<CkWildcardCC>(Pattern, 0);
	CK_GUARD_RET(Loc.size() == 1, false);

	CK_TRACE_INFO("FOUND: CHwFullScreenRenderTarget_Present=%p", Loc[0]);
	CHwFullScreenRenderTarget_Present_Loc = Loc[0];

	auto Offset = *(UINT8*)(Loc[0] + 223 + 3);
	CK_TRACE_INFO("FOUND: CHwFullScreenRenderTarget_SwapChainBase_Offset=0x%X", (UINT)Offset);
	CK_GUARD_RET(Offset, false);
	CHwFullScreenRenderTarget_SwapChainBase_Offset = Offset;

	return true;
}

static __int64 __fastcall CHwFullScreenRenderTarget_Present_Hook(class CHwFullScreenRenderTarget* pThis, __int64 a2, char a3, const struct RenderTargetPresentParameters* a4)
{
	// TESTED ON: Win Home Version 10.0.18363.720 ; dwmcore.dll -> MD5 841d051475be5af7239189ef9234561d

	_PresentId++;
	//CK_TRACE_INFO("CHwFullScreenRenderTarget_Present");

	if (!_Device)
	{
		CK_TRACE_INFO("GET DEVICE..");

		LPVOID pSwapChainBase = *(LPVOID*)((UINT8*)pThis + CHwFullScreenRenderTarget_SwapChainBase_Offset);
		CK_TRACE_INFO("pSwapChainBase=%p", pSwapChainBase);
		if (pSwapChainBase)
		{
			IDXGISwapChain* pDxgiSwapChain = *(IDXGISwapChain**)((UINT8*)pSwapChainBase + _CDWMSwapChain_DxgiSwapChain_Offset);
			CK_TRACE_INFO("pDxgiSwapChain=%p", pDxgiSwapChain);
			if (pDxgiSwapChain)
			{
				if ((pDxgiSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&_Device) == S_OK))
				{
					pDxgiSwapChain->AddRef();
					CK_TRACE_INFO("FOUND: IDXGISwapChain=%p ID3D11Device=%p", pDxgiSwapChain, _Device);

					dwm_overlay_init(pDxgiSwapChain, _Device);
				}
			}
		}
	}

	if (_Device)
	{
		dwm_overlay_present();
	}

	return ORIG_FUNC(CHwFullScreenRenderTarget_Present)(pThis, a2, a3, a4);
}

//===============================================================================================//

static unsigned __stdcall InjectedThread(LPVOID lpParameter)
{
	CK_TRACE_INFO("ENTER: InjectedThread");

	try
	{
		do
		{
			PLH::CapstoneDisassembler Dis(PLH::Mode::x64);

			Find_SwapChain_Offset();
			Find_CHwFullScreenRenderTarget_Present();

			CK_GUARD_BRK(_CDWMSwapChain_DxgiSwapChain_Offset);
			CK_GUARD_BRK(CHwFullScreenRenderTarget_Present_Loc);

			{
				SCOPED_HOOK(Dis, CHwFullScreenRenderTarget_Present);

				float accum = 0;
				auto t0 = GetTickCount64();

				while (!_StopFlag)
				{
					auto t1 = GetTickCount64();
					auto dt = t1 - t0;
					accum += dt * 0.001f;
					t0 = t1;

					if (accum >= 1)
					{
						accum = 0;
						CK_TRACE_INFO("%d", _PresentId);
						_PresentId = 0;
					}

					if (GetAsyncKeyState(VK_SUBTRACT) & 0x8000) { _StopFlag = true; break; }

					Sleep(100); // LOL
				}
			}

			dwm_overlay_shutdown();
		}
		while (0);
	}
	catch (...)
	{
		CK_TRACE_ERROR("EXCEPTION: InjectedThread");
	}

	CK_TRACE_INFO("LEAVE: InjectedThread");
	_endthreadex(0);
	return 0;
}

//===============================================================================================//

extern "C" void __stdcall dwm_hook_attach()
{
	CK_OutputDebugStringA("## dwm_hook_attach ##");
	_StopFlag = false;
	_beginthreadex(NULL, 0, InjectedThread, NULL, 0, NULL);
}

extern "C" void __stdcall dwm_hook_detach()
{
	CK_OutputDebugStringA("## dwm_hook_detach ##");
	_StopFlag = true;
}
