# FindWdkKm.cmake - Probe for the WDK 10.0.26100.0 kernel-mode SDK.
#
# Sets:
#   EDR_KM_SDK_FOUND  ON/OFF
#   EDR_WDK_INC_KM, EDR_WDK_INC_KMCRT, EDR_WDK_INC_UM, EDR_WDK_INC_SHARED
#   EDR_WDK_LIB_KM_X64
#   EDR_WDK_NTOSKRNL_LIB, EDR_WDK_HAL_LIB
#
# Every missing prerequisite is reported with its exact expected path.
# KMDF (wdf.h) is intentionally never probed or used.

set(_EDR_KITS_ROOT "$ENV{KitsRoot10}")
if(NOT _EDR_KITS_ROOT)
    set(_EDR_KITS_ROOT "C:/Program Files (x86)/Windows Kits/10/")
endif()
file(TO_CMAKE_PATH "${_EDR_KITS_ROOT}" _EDR_KITS_ROOT)
# TO_CMAKE_PATH strips trailing slashes; the paths below assume exactly one.
string(REGEX REPLACE "/+$" "" _EDR_KITS_ROOT "${_EDR_KITS_ROOT}")
set(_EDR_KITS_ROOT "${_EDR_KITS_ROOT}/")

set(_EDR_WDK_VER "10.0.26100.0")

set(EDR_WDK_INC_KM     "${_EDR_KITS_ROOT}Include/${_EDR_WDK_VER}/km")
set(EDR_WDK_INC_KMCRT  "${_EDR_KITS_ROOT}Include/${_EDR_WDK_VER}/km/crt")
set(EDR_WDK_INC_UM     "${_EDR_KITS_ROOT}Include/${_EDR_WDK_VER}/um")
set(EDR_WDK_INC_SHARED "${_EDR_KITS_ROOT}Include/${_EDR_WDK_VER}/shared")
set(EDR_WDK_LIB_KM_X64 "${_EDR_KITS_ROOT}Lib/${_EDR_WDK_VER}/km/x64")

# 10.0.26100.0's shared headers reference specstrings_strict.h which ships
# only in other SDK versions; add a newer shared dir as a fallback include
# when present (empty otherwise, so older SDK-only machines still build).
set(EDR_WDK_INC_SHARED_FALLBACK "")
if(EXISTS "${_EDR_KITS_ROOT}Include/10.0.28000.0/shared/specstrings_strict.h")
    set(EDR_WDK_INC_SHARED_FALLBACK
        "/I${_EDR_KITS_ROOT}Include/10.0.28000.0/shared")
elseif(EXISTS "${_EDR_KITS_ROOT}Include/10.0.22621.0/shared/specstrings_strict.h")
    set(EDR_WDK_INC_SHARED_FALLBACK
        "/I${_EDR_KITS_ROOT}Include/10.0.22621.0/shared")
endif()

set(EDR_KM_SDK_FOUND ON)

macro(_edr_km_require_path _path _desc)
    if(NOT EXISTS "${_path}")
        message(STATUS "[FindWdkKm] MISSING ${_desc}: ${_path}")
        set(EDR_KM_SDK_FOUND OFF)
    endif()
endmacro()

_edr_km_require_path("${EDR_WDK_INC_KM}/ntddk.h"        "kernel header")
_edr_km_require_path("${EDR_WDK_INC_KMCRT}"             "kernel CRT include dir")
_edr_km_require_path("${EDR_WDK_INC_UM}/Windows.h"      "user-mode header")
_edr_km_require_path("${EDR_WDK_INC_SHARED}"            "shared include dir")
_edr_km_require_path("${EDR_WDK_LIB_KM_X64}/ntoskrnl.lib" "ntoskrnl import lib")
_edr_km_require_path("${EDR_WDK_LIB_KM_X64}/hal.lib"      "hal import lib")

set(EDR_WDK_NTOSKRNL_LIB "${EDR_WDK_LIB_KM_X64}/ntoskrnl.lib")
set(EDR_WDK_HAL_LIB      "${EDR_WDK_LIB_KM_X64}/hal.lib")

if(EDR_KM_SDK_FOUND)
    message(STATUS "[FindWdkKm] kernel-mode SDK found (WDK ${_EDR_WDK_VER})")
else()
    message(STATUS "[FindWdkKm] kernel-mode SDK incomplete; edrdrv target will be skipped")
endif()
