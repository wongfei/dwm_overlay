#include "ck/ck.h"
#include "ck/dwm_overlay.h"
#include <d3dcompiler.h>
#include <directxmath.h>

#pragma comment(lib, "d3dcompiler.lib")
using namespace DirectX;

#define STRINGIFY(X) #X

static const char* shader_code = STRINGIFY
(
	cbuffer ConstantBuffer : register( b0 )
	{
		matrix World;
		matrix View;
		matrix Projection;
	}
	struct VS_OUTPUT
	{
		float4 Pos : SV_POSITION;
		float4 Color : COLOR0;
	};
	VS_OUTPUT VS( float4 Pos : POSITION, float4 Color : COLOR )
	{
		VS_OUTPUT output = (VS_OUTPUT)0;
		output.Pos = mul( Pos, World );
		output.Pos = mul( output.Pos, View );
		output.Pos = mul( output.Pos, Projection );
		output.Color = Color;
		return output;
	}
	float4 PS( VS_OUTPUT input ) : SV_Target
	{
		return input.Color;
	}
);

struct SimpleVertex
{
    XMFLOAT3 Pos;
    XMFLOAT4 Color;
};

struct ConstantBuffer
{
	XMMATRIX mWorld;
	XMMATRIX mView;
	XMMATRIX mProjection;
};

//===============================================================================================//

struct overlay_state
{
	TScopedHandle<IDXGISwapChain*, COM_traits> swap_chain_ptr;
	TScopedHandle<ID3D11Device*, COM_traits> device_ptr;
	TScopedHandle<ID3D11DeviceContext*, COM_traits> device_context_ptr;

	TScopedHandle<ID3D11Texture2D*, COM_traits> backbuffer_ptr;
	TScopedHandle<ID3D11RenderTargetView*, COM_traits> rtview_ptr;
	TScopedHandle<ID3D11RasterizerState*, COM_traits> rasterizer_state;
	TScopedHandle<ID3D11RasterizerState*, COM_traits> rasterizer_state_ov;

	TScopedHandle<ID3D11VertexShader*, COM_traits> vertex_shader_ptr;
	TScopedHandle<ID3D11PixelShader*, COM_traits> pixel_shader_ptr;
	TScopedHandle<ID3D11InputLayout*, COM_traits> input_layout_ptr;
	TScopedHandle<ID3D11Buffer*, COM_traits> vertex_buffer_ptr;
	TScopedHandle<ID3D11Buffer*, COM_traits> index_buffer_ptr;
	TScopedHandle<ID3D11Buffer*, COM_traits> const_buffer_ptr;

	ULONGLONG t0 = 0;
	float accum = 0;

	overlay_state() {}
	~overlay_state() { shutdown(); }

	bool init(IDXGISwapChain* SwapChain, ID3D11Device* Device);
	void present();
	void shutdown();
};

static overlay_state* _state = NULL;

//===============================================================================================//

bool overlay_state::init(IDXGISwapChain* SwapChain, ID3D11Device* Device)
{
	do
	{
		// context

		swap_chain_ptr = SwapChain;
		device_ptr = Device;

		device_ptr->GetImmediateContext(&device_context_ptr);
		CK_GUARD_BRK(device_context_ptr);

		CK_GUARD_BRK(S_OK == swap_chain_ptr->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&backbuffer_ptr));
		CK_GUARD_BRK(S_OK == device_ptr->CreateRenderTargetView(*backbuffer_ptr, NULL, &rtview_ptr));

		device_context_ptr->RSGetState(&rasterizer_state);

		D3D11_RASTERIZER_DESC raster_desc;
		ZeroMemory(&raster_desc, sizeof(raster_desc));
		raster_desc.FillMode = D3D11_FILL_SOLID; // D3D11_FILL_WIREFRAME;
		raster_desc.CullMode = D3D11_CULL_BACK; //D3D11_CULL_NONE;
		CK_GUARD_BRK(S_OK == device_ptr->CreateRasterizerState(&raster_desc, &rasterizer_state_ov));

		// shader

		D3D_SHADER_MACRO shader_macro[] = { NULL, NULL };
		ID3DBlob *vs_blob_ptr = NULL, *ps_blob_ptr = NULL, *error_blob = NULL;

		CK_GUARD_BRK(S_OK == D3DCompile(shader_code, strlen(shader_code), NULL, shader_macro, NULL, "VS", "vs_4_0", 0, 0, &vs_blob_ptr, &error_blob));
		CK_GUARD_BRK(S_OK == D3DCompile(shader_code, strlen(shader_code), NULL, shader_macro, NULL, "PS", "ps_4_0", 0, 0, &ps_blob_ptr, &error_blob));

		CK_GUARD_BRK(S_OK == device_ptr->CreateVertexShader(vs_blob_ptr->GetBufferPointer(), vs_blob_ptr->GetBufferSize(), NULL, &vertex_shader_ptr));
		CK_GUARD_BRK(S_OK == device_ptr->CreatePixelShader(ps_blob_ptr->GetBufferPointer(), ps_blob_ptr->GetBufferSize(), NULL, &pixel_shader_ptr));

		// layout

		D3D11_INPUT_ELEMENT_DESC element_desc[] =
		{
			{ "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
			{ "COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
		};

		CK_GUARD_BRK(S_OK == device_ptr->CreateInputLayout(element_desc, ARRAYSIZE(element_desc), vs_blob_ptr->GetBufferPointer(), vs_blob_ptr->GetBufferSize(), &input_layout_ptr));

		// buffers

		SimpleVertex vertices[] =
		{
			{ XMFLOAT3( -1.0f, 1.0f, -1.0f ), XMFLOAT4( 0.0f, 0.0f, 1.0f, 1.0f ) },
			{ XMFLOAT3( 1.0f, 1.0f, -1.0f ), XMFLOAT4( 0.0f, 1.0f, 0.0f, 1.0f ) },
			{ XMFLOAT3( 1.0f, 1.0f, 1.0f ), XMFLOAT4( 0.0f, 1.0f, 1.0f, 1.0f ) },
			{ XMFLOAT3( -1.0f, 1.0f, 1.0f ), XMFLOAT4( 1.0f, 0.0f, 0.0f, 1.0f ) },
			{ XMFLOAT3( -1.0f, -1.0f, -1.0f ), XMFLOAT4( 1.0f, 0.0f, 1.0f, 1.0f ) },
			{ XMFLOAT3( 1.0f, -1.0f, -1.0f ), XMFLOAT4( 1.0f, 1.0f, 0.0f, 1.0f ) },
			{ XMFLOAT3( 1.0f, -1.0f, 1.0f ), XMFLOAT4( 1.0f, 1.0f, 1.0f, 1.0f ) },
			{ XMFLOAT3( -1.0f, -1.0f, 1.0f ), XMFLOAT4( 0.0f, 0.0f, 0.0f, 1.0f ) },
		};

		WORD indices[] =
		{
			3,1,0,
			2,1,3,

			0,5,4,
			1,5,0,

			3,4,7,
			0,4,3,

			1,6,5,
			2,6,1,

			2,7,6,
			3,7,2,

			6,4,5,
			7,4,6,
		};

		D3D11_BUFFER_DESC bd = {};
		D3D11_SUBRESOURCE_DATA data = {};

		bd.Usage = D3D11_USAGE_DEFAULT;
		bd.ByteWidth = sizeof(SimpleVertex) * 8;
		bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
		bd.CPUAccessFlags = 0;
		data.pSysMem = vertices;
		CK_GUARD_BRK(S_OK == device_ptr->CreateBuffer(&bd, &data, &vertex_buffer_ptr));

		bd.Usage = D3D11_USAGE_DEFAULT;
		bd.ByteWidth = sizeof(WORD) * 36;
		bd.BindFlags = D3D11_BIND_INDEX_BUFFER;
		bd.CPUAccessFlags = 0;
		data.pSysMem = indices;
		CK_GUARD_BRK(S_OK == device_ptr->CreateBuffer(&bd, &data, &index_buffer_ptr));

		bd.Usage = D3D11_USAGE_DEFAULT;
		bd.ByteWidth = sizeof(ConstantBuffer);
		bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
		bd.CPUAccessFlags = 0;
		CK_GUARD_BRK(S_OK == device_ptr->CreateBuffer(&bd, NULL, &const_buffer_ptr));

		// SUCCESS

		t0 = GetTickCount64();

		CK_TRACE_INFO("dwm_overlay_init: OK");
		return true;
	}
	while (0);

	shutdown();
	return false;
}

void overlay_state::present()
{
	auto t1 = GetTickCount64();
	float dt = (t1 - t0) * 0.001f;
	accum += dt;
	t0 = t1;

	D3D11_TEXTURE2D_DESC bb;
	ZeroMemory(&bb, sizeof(bb));
	backbuffer_ptr->GetDesc(&bb);

	XMMATRIX world = XMMatrixRotationY(accum);
	XMVECTOR eye = XMVectorSet(0.0f, 1.0f, -5.0f, 0.0f);
	XMVECTOR at = XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f);
	XMVECTOR up = XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f);
	XMMATRIX view = XMMatrixLookAtLH(eye, at, up);
	XMMATRIX proj = XMMatrixPerspectiveFovLH(XM_PIDIV2, bb.Width / (FLOAT)bb.Height, 0.01f, 100.0f);

	//float color[4] = { 0, 0, 0, 0 };
	//device_context_ptr->ClearRenderTargetView(*rtview_ptr, color);
	device_context_ptr->OMSetRenderTargets(1, &rtview_ptr, NULL);

	D3D11_VIEWPORT viewport = { 0.0f, 0.0f, (float)bb.Width, (float)bb.Height, 0.0f, 1.0f };
	device_context_ptr->RSSetViewports(1, &viewport);
	device_context_ptr->RSSetState(*rasterizer_state_ov);

	device_context_ptr->IASetInputLayout(*input_layout_ptr);
	device_context_ptr->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

	UINT stride = sizeof(SimpleVertex), offset = 0;
	device_context_ptr->IASetVertexBuffers(0, 1, &vertex_buffer_ptr, &stride, &offset);
	device_context_ptr->IASetIndexBuffer(*index_buffer_ptr, DXGI_FORMAT_R16_UINT, 0);

	ConstantBuffer cb;
	cb.mWorld = XMMatrixTranspose(world);
	cb.mView = XMMatrixTranspose(view);
	cb.mProjection = XMMatrixTranspose(proj);
	device_context_ptr->UpdateSubresource( *const_buffer_ptr, 0, NULL, &cb, 0, 0 );

	device_context_ptr->VSSetShader(*vertex_shader_ptr, NULL, 0);
	device_context_ptr->VSSetConstantBuffers(0, 1, &const_buffer_ptr);
	device_context_ptr->PSSetShader(*pixel_shader_ptr, NULL, 0);
	device_context_ptr->DrawIndexed(36, 0, 0);

	device_context_ptr->RSSetState(*rasterizer_state);
}

void overlay_state::shutdown()
{
}

//===============================================================================================//

bool dwm_overlay_init(IDXGISwapChain* SwapChain, ID3D11Device* Device)
{
	CK_TRACE_INFO("dwm_overlay_init: SwapChain=%p Device=%p", SwapChain, Device);
	CK_GUARD_RET(!_state, false);

	_state = new overlay_state();
	if (!_state->init(SwapChain, Device))
	{
		SafeDelete(_state);
		return false;
	}

	return true;
}

void dwm_overlay_present()
{
	if (_state)
	{
		_state->present();
	}
}

void dwm_overlay_shutdown()
{
	if (_state)
	{
		CK_TRACE_INFO("dwm_overlay_shutdown");
		SafeDelete(_state);
	}
}
