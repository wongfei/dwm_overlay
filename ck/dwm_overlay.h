#pragma once

bool dwm_overlay_init(IDXGISwapChain* SwapChain, ID3D11Device* Device);
void dwm_overlay_present();
void dwm_overlay_shutdown();
