#include "ck/ck.h"
#include "ck/dwm_hook.h"
#include "ck/dwm_overlay.h"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/Detour/x64Detour.hpp"

static volatile int _StopFlag = false;
static ID3D11Device* _Device = NULL;
static UINT32 _SwapChainOffset = 0;
static unsigned int _PresentId = 0;

//===============================================================================================//

#define DECL_HOOK(Name)\
	static LPVOID Name##_Loc = NULL;\
	static uint64_t Name##_Orig = 0;

#define ORIG_FUNC(Name) ((Name##_Proto)Name##_Orig)

#define SCOPED_HOOK_BRK(Dis, Name) ScopedDetour Hook_##Name(Dis, #Name, Name##_Loc, &Name##_Hook, &Name##_Orig); CK_GUARD_BRK(Hook_##Name.Hooked);

struct ScopedDetour
{
	PLH::x64Detour Detour;
	bool Hooked;

	inline ScopedDetour(PLH::CapstoneDisassembler& Dis, const char* Name, void* Loc, void* Hook, uint64_t* Orig) :
		Detour((char*)Loc, (char*)Hook, Orig, Dis)
	{ 
		CK_TRACE_INFO("HOOK %s %p", Name, Loc);
		Hooked = Detour.hook();
		CK_TRACE_INFO("%s", (Hooked ? "OK" : "FAIL"));
	}

	inline ~ScopedDetour()
	{ 
		if (Hooked) { Detour.unHook(); }
	}
};

//===============================================================================================//

// Version 10.0.17763.973
// MD5 ea6256b1c5bc75242cc92bbcfd842832 dwmcore.dll

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

	_SwapChainOffset = *(UINT32*)(Loc[0] + 9);
	CK_TRACE_INFO("FOUND: SwapChainOffset=0x%X", (UINT)_SwapChainOffset);
	CK_GUARD_RET(_SwapChainOffset, false);

	return true;
}

//===============================================================================================//

typedef __int64 (__fastcall *CD3DDeviceLevel1_PresentSwapChain_Proto)(
	class CD3DDeviceLevel1* pThis, 
	struct CSwapChainBase* pBase, 
	const struct CRegion* pRegion,
	unsigned int uiUnk1, 
	unsigned int uiUnk2, 
	const struct RenderTargetPresentParameters* pParams);

DECL_HOOK(CD3DDeviceLevel1_PresentSwapChain)

static bool Find_CD3DDeviceLevel1_PresentSwapChain()
{
	// __int64 __fastcall CD3DDeviceLevel1::PresentSwapChain(CD3DDeviceLevel1 *this, struct CSwapChainBase *, const struct CRegion *, unsigned int, unsigned int, const struct RenderTargetPresentParameters *)
	auto Pattern = CkParseByteArray(
		"48 89 5C 24 10" // mov     [rsp+arg_8], rbx
		"48 89 6C 24 18" // mov     [rsp+arg_10], rbp
		"56" // push    rsi
		"57" // push    rdi
		"41 56" // push    r14
		"48 83 EC 30" // sub     rsp, 30h
		"8B 99 50 03 00 00" // mov     ebx, [rcx+350h]
		"41 8B F1" // mov     esi, r9d
		"49 8B E8" // mov     rbp, r8
		"4C 8B F2" // mov     r14, rdx
		"48 8B F9" // mov     rdi, rcx
		"85 DB" // test    ebx, ebx
		"0F 88 CC CC CC CC" // js      loc_1801416AD
		"80 3D CC CC CC CC 00" // cmp     cs:?g_fForceDeviceLost@@3_NA, 0 ; bool g_fForceDeviceLost
		"0F 85 CC CC CC CC" // jnz     loc_180141636
		"48 8B 44 24 78" // mov     rax, [rsp+48h+arg_28]
		"44 8B CE" // mov     r9d, esi        ; unsigned int
		"44 8B 44 24 70" // mov     r8d, [rsp+48h+arg_20] ; unsigned int
		"48 8B D5" // mov     rdx, rbp        ; struct CRegion *
		"49 8B CE" // mov     rcx, r14        ; this
		"48 89 44 24 20" // mov     [rsp+48h+var_28], rax ; struct RenderTargetPresentParameters *
		"E8 CC CC CC CC" // call    ?Present@CSwapChainBase@@QEAAJAEBVCRegion@@IIPEBURenderTargetPresentParameters@@@Z ; CSwapChainBase::Present(CRegion const &,uint,uint,RenderTargetPresentParameters const *)
		"8B D8" // mov     ebx, eax
		"85 C0" // test    eax, eax
		"0F 88 CC CC CC CC" // js      loc_1801416A0
		"40 F6 C6 01" // test    sil, 1
		"75 1C" // jnz     short loc_1800DEBEE
		"48 8B 0D CC CC CC CC" // mov     rcx, cs:?g_pComposition@@3PEAVCCrossThreadComposition@@EA ; CCrossThreadComposition * g_pComposition
		"48 8B 91 70 01 00 00" // mov     rdx, [rcx+170h]
		"48 89 97 F8 03 00 00" // mov     [rdi+3F8h], rdx
		"C6 87 04 04 00 00 00" // mov     byte ptr [rdi+404h], 0
		"41 B8 01 00 00 00" // mov     r8d, 1
		"8B D3" // mov     edx, ebx
		"48 8B CF" // mov     rcx, rdi
		"E8 CC CC CC CC" // call    ?TranslateDXGIorD3DErrorInContext@CD3DDeviceLevel1@@QEAAJJW4Enum@DXGIFunctionContext@@@Z ; CD3DDeviceLevel1::TranslateDXGIorD3DErrorInContext(long,DXGIFunctionContext::Enum)
		"48 8B CF" // mov     rcx, rdi        ; this
		"8B D8" // mov     ebx, eax
		"E8 CC CC CC CC" // call    ?ProcessDeviceLost@CD3DDeviceLevel1@@AEAAXXZ ; CD3DDeviceLevel1::ProcessDeviceLost(void)
		"48 8B 6C 24 60" // mov     rbp, [rsp+48h+arg_10]
		"8B C3" // mov     eax, ebx
		"48 8B 5C 24 58" // mov     rbx, [rsp+48h+arg_8]
		"48 83 C4 30" // add     rsp, 30h
		"41 5E" // pop     r14
		"5F" // pop     rdi
		"5E" // pop     rsi
		"C3" // retn
	);

	auto Loc = CkFindPatternIntern<CkWildcardCC>(Pattern, 0);
	CK_GUARD_RET(Loc.size() == 1, false);

	CK_TRACE_INFO("FOUND: CD3DDeviceLevel1_PresentSwapChain=%p", Loc[0]);
	CD3DDeviceLevel1_PresentSwapChain_Loc = Loc[0];

	return true;
}

static __int64 __fastcall CD3DDeviceLevel1_PresentSwapChain_Hook(
	class CD3DDeviceLevel1* pThis, 
	struct CSwapChainBase* pSwapChain, 
	const struct CRegion* pRegion,
	unsigned int uiUnk1, 
	unsigned int uiUnk2, 
	const struct RenderTargetPresentParameters* pParams)
{
	_PresentId++;

	// TODO: not tested on multi device/monitor configuration
	if (!_Device)
	{
		IDXGISwapChain* SwapChain = *(IDXGISwapChain**)((UINT8*)pSwapChain + _SwapChainOffset);

		if (SwapChain && (SwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&_Device) == S_OK))
		{
			SwapChain->AddRef();
			CK_TRACE_INFO("FOUND: IDXGISwapChain=%p ID3D11Device=%p", SwapChain, _Device);
			dwm_overlay_init(SwapChain, _Device);
		}
	}

	if (_Device)
	{
		dwm_overlay_present();
	}

	return ORIG_FUNC(CD3DDeviceLevel1_PresentSwapChain)(pThis, pSwapChain, pRegion, uiUnk1, uiUnk2, pParams);
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

			CK_GUARD_BRK(Find_SwapChain_Offset());
			CK_GUARD_BRK(Find_CD3DDeviceLevel1_PresentSwapChain());

			{
				SCOPED_HOOK_BRK(Dis, CD3DDeviceLevel1_PresentSwapChain);

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
