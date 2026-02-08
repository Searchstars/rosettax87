#!/bin/zsh
set -euo pipefail

# Minimal runner for Endfield under the AstroWine + rosettax87 syscall hook setup.
# Keeps defaults in one place so we can reproduce crashes consistently.

WINE_DIR_DEFAULT="/Users/searchstars/Downloads/wine"
ENDFIELD_EXE_DEFAULT="/Users/searchstars/Downloads/Endfield Game/Endfield.exe"
WINELOADER_DEFAULT="${WINE_DIR_DEFAULT}/loader/wine64"
ROSETTA_HOOKS_DEFAULT="/Users/searchstars/Documents/AstroWine/rosettax87/build/rosettax87"

WINEPREFIX_DEFAULT="/Users/searchstars/Documents/AstroWine/rosettax87/.wineprefix"
LOG_PATH_DEFAULT="/tmp/astrowine_run.log"

WINELOADER="${WINELOADER:-$WINELOADER_DEFAULT}"
ENDFIELD_EXE="${ENDFIELD_EXE:-$ENDFIELD_EXE_DEFAULT}"
ROSETTA_HOOKS="${ROSETTA_HOOKS:-$ROSETTA_HOOKS_DEFAULT}"
WINEPREFIX="${WINEPREFIX:-$WINEPREFIX_DEFAULT}"
LOG_PATH="${LOG_PATH:-$LOG_PATH_DEFAULT}"

NO_HOOK=0
HOOK_OFF=0
NO_INTERCEPT=0
NO_PAYLOAD_LOGS=0
STATE_ADDR=""
STATE_SIZE=""
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
    --no-hook)
      NO_HOOK=1
      shift
      ;;
    --hook-off)
      HOOK_OFF=1
      shift
      ;;
    --no-intercept)
      NO_INTERCEPT=1
      shift
      ;;
    --no-payload-logs)
      NO_PAYLOAD_LOGS=1
      shift
      ;;
    --state-addr)
      STATE_ADDR="$2"
      shift 2
      ;;
    --state-size)
      STATE_SIZE="$2"
      shift 2
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
    --hooks)
      ROSETTA_HOOKS="$2"
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

if [[ "$NO_HOOK" == 1 ]]; then
  ROSETTA_HOOKS=""
fi
export ASTROWINE_ROSETTA_HOOKS_PATH="$ROSETTA_HOOKS"
if [[ "$HOOK_OFF" == 1 ]]; then
  export ASTROWINE_HELPER_INLINE=0
  export ASTROWINE_HELPER_INLINE_C=0
else
  export ASTROWINE_HELPER_INLINE="${ASTROWINE_HELPER_INLINE:-1}"
  export ASTROWINE_HELPER_INLINE_C="${ASTROWINE_HELPER_INLINE_C:-1}"
fi
if [[ -n "$STATE_ADDR" ]]; then
  export ASTROWINE_STATE_ADDR="$STATE_ADDR"
fi
if [[ -n "$STATE_SIZE" ]]; then
  export ASTROWINE_STATE_SIZE="$STATE_SIZE"
fi
export ASTROWINE_SYSCALL_INTERCEPT="${ASTROWINE_SYSCALL_INTERCEPT:-1}"
export ASTROWINE_WINE_SHM="${ASTROWINE_WINE_SHM:-1}"
export ASTROWINE_WAIT_CHILD="${ASTROWINE_WAIT_CHILD:-1}"
export ASTROWINE_LOGS="${ASTROWINE_LOGS:-1}"
export ASTROWINE_SHM_ACTIVE_PULL="${ASTROWINE_SHM_ACTIVE_PULL:-1}"
export ASTROWINE_SHM_TRANSLATE="${ASTROWINE_SHM_TRANSLATE:-0}"
export ASTROWINE_ACE_AUTOLOAD="${ASTROWINE_ACE_AUTOLOAD:-1}"
if [[ "$NO_INTERCEPT" == 1 ]]; then
  export ASTROWINE_SYSCALL_INTERCEPT=0
fi

# Optional extra verbosity.
export ASTROWINE_HOOK_LOGS="${ASTROWINE_HOOK_LOGS:-1}"
export ASTROWINE_PAYLOAD_LOG_SYSCALL="${ASTROWINE_PAYLOAD_LOG_SYSCALL:-1}"
export ASTROWINE_PAYLOAD_LOG_RESOLVE="${ASTROWINE_PAYLOAD_LOG_RESOLVE:-1}"
if [[ "$NO_PAYLOAD_LOGS" == 1 ]]; then
  export ASTROWINE_PAYLOAD_LOG_SYSCALL=0
  export ASTROWINE_PAYLOAD_LOG_RESOLVE=0
fi

echo "WINELOADER=$WINELOADER"
echo "EXE=$ENDFIELD_EXE"
echo "WINEPREFIX=$WINEPREFIX"
echo "ROSETTA_HOOKS=$ROSETTA_HOOKS"
echo "LOG_PATH=$LOG_PATH"

"$WINELOADER" "$ENDFIELD_EXE" "$@" 2>&1 | tee "$LOG_PATH"
