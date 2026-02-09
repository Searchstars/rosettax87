#!/bin/zsh
set -euo pipefail

# Minimal runner for Endfield under AstroWine with the rosettax87 loader.

WINE_DIR_DEFAULT="/Users/searchstars/Downloads/wine"
ENDFIELD_EXE_DEFAULT="/Users/searchstars/Downloads/Endfield Game/Endfield.exe"
WINELOADER_DEFAULT="${WINE_DIR_DEFAULT}/loader/wine64"
ROSETTA_LOADER_DEFAULT="/Users/searchstars/Documents/AstroWine/rosettax87/build/rosettax87"

WINEPREFIX_DEFAULT="/Users/searchstars/Documents/AstroWine/rosettax87/.wineprefix"
LOG_PATH_DEFAULT="/tmp/astrowine_run.log"

WINELOADER="${WINELOADER:-$WINELOADER_DEFAULT}"
ENDFIELD_EXE="${ENDFIELD_EXE:-$ENDFIELD_EXE_DEFAULT}"
ROSETTA_LOADER="${ROSETTA_LOADER:-$ROSETTA_LOADER_DEFAULT}"
WINEPREFIX="${WINEPREFIX:-$WINEPREFIX_DEFAULT}"
LOG_PATH="${LOG_PATH:-$LOG_PATH_DEFAULT}"

WINEDEBUG_OVERRIDE=""
WINE_SEH_VERBOSE_OVERRIDE=""
MACDRV_IGNORE_GFX_ACCESS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --winedebug)
      WINEDEBUG_OVERRIDE="$2"
      shift 2
      ;;
    --wine-seh-verbose)
      WINE_SEH_VERBOSE_OVERRIDE="$2"
      shift 2
      ;;
    --macdrv-ignore-graphic-access)
      MACDRV_IGNORE_GFX_ACCESS=1
      shift
      ;;
    --wineprefix)
      WINEPREFIX="$2"
      shift 2
      ;;
    --log-path)
      LOG_PATH="$2"
      shift 2
      ;;
    --exe)
      ENDFIELD_EXE="$2"
      shift 2
      ;;
    --wineloader)
      WINELOADER="$2"
      shift 2
      ;;
    --rosetta-loader)
      ROSETTA_LOADER="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

rm -f "$LOG_PATH"
mkdir -p "$WINEPREFIX"

export WINEPREFIX
if [[ -n "$WINE_SEH_VERBOSE_OVERRIDE" ]]; then
  export WINE_SEH_VERBOSE="$WINE_SEH_VERBOSE_OVERRIDE"
else
  export WINE_SEH_VERBOSE="${WINE_SEH_VERBOSE:-1}"
fi
if [[ -n "$WINEDEBUG_OVERRIDE" ]]; then
  export WINEDEBUG="$WINEDEBUG_OVERRIDE"
else
  export WINEDEBUG="${WINEDEBUG:--all,+seh,+tid}"
fi
if [[ "$MACDRV_IGNORE_GFX_ACCESS" == 1 ]]; then
  export WINE_MACDRV_IGNORE_GRAPHIC_ACCESS=1
fi

export ASTROWINE_ROSETTA_HOOKS_PATH="$ROSETTA_LOADER"
export ASTROWINE_LOGS="${ASTROWINE_LOGS:-1}"
export ASTROWINE_SHM_ACTIVE_PULL="${ASTROWINE_SHM_ACTIVE_PULL:-1}"
export ASTROWINE_SHM_TRANSLATE="${ASTROWINE_SHM_TRANSLATE:-0}"
export ASTROWINE_ACE_AUTOLOAD="${ASTROWINE_ACE_AUTOLOAD:-1}"

echo "WINELOADER=$WINELOADER"
echo "EXE=$ENDFIELD_EXE"
echo "WINEPREFIX=$WINEPREFIX"
echo "ROSETTA_LOADER=$ROSETTA_LOADER"
echo "LOG_PATH=$LOG_PATH"

"$WINELOADER" "$ENDFIELD_EXE" "$@" 2>&1 | tee "$LOG_PATH"
