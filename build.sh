#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./build.sh [OUTPUT_DIRECTORY]

Build gosmb for Windows, Linux, and macOS on AMD64 and ARM64.
The default output directory is builds/ beside this script. Relative output
paths are resolved from the current directory.

Files are named gosmb-<os>-<architecture>, with .exe for Windows.
Existing binaries are replaced only after all six builds succeed.
USAGE
}

if (( $# > 1 )); then
    usage >&2
    exit 2
fi
case "${1-}" in
    -h|--help)
        usage
        exit 0
        ;;
    -*)
        printf 'Unknown option: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
esac

if ! command -v go >/dev/null 2>&1; then
    printf 'Go is required to build gosmb.\n' >&2
    exit 1
fi

project_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
output_dir="${1-$project_dir/builds}"
mkdir -p -- "$output_dir"
output_dir="$(CDPATH= cd -- "$output_dir" && pwd -P)"
stage_dir="$(mktemp -d "$output_dir/.gosmb-build.XXXXXXXX")"
trap 'rm -rf -- "$stage_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd -- "$project_dir"
artifacts=()
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    target_os="${target%/*}"
    target_arch="${target#*/}"
    platform="$target_os"
    if [[ "$platform" == darwin ]]; then
        platform=macos
    fi
    filename="gosmb-$platform-$target_arch"
    if [[ "$target_os" == windows ]]; then
        filename+=.exe
    fi
    artifacts+=("$filename")

    printf 'Building %s/%s...\n' "$platform" "$target_arch"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
        go build -trimpath -o "$stage_dir/$filename" .
done

# Check every destination before replacing any previous binary.
for filename in "${artifacts[@]}"; do
    if [[ -d "$output_dir/$filename" ]]; then
        printf 'Cannot replace a directory with a build: %s\n' "$output_dir/$filename" >&2
        exit 1
    fi
done
for filename in "${artifacts[@]}"; do
    mv -f -- "$stage_dir/$filename" "$output_dir/$filename"
done
printf 'Builds saved in %s\n' "$output_dir"
