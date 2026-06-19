package vaultblob

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	libLoaded bool
	libOnce   sync.Once
	libErr    error
)

func ensureLib() error {
	libOnce.Do(func() {
		if libBinary == nil {
			libErr = errors.New("vaultblob: native library not available for " + runtime.GOOS + "/" + runtime.GOARCH)
			return
		}

		cacheDir, err := os.UserCacheDir()
		if err != nil {
			cacheDir = os.TempDir()
		}
		libDir := filepath.Join(cacheDir, "vaultblob-go")
		os.MkdirAll(libDir, 0755)
		libPath := filepath.Join(libDir, libFilename())

		os.WriteFile(libPath, libBinary, 0755)

		handle, err := purego.Dlopen(libPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			libErr = err
			return
		}

		purego.RegisterLibFunc(&vaultOpen, handle, "vaultblob_open")
		purego.RegisterLibFunc(&vaultOpenExisting, handle, "vaultblob_open_existing")
		purego.RegisterLibFunc(&vaultClose, handle, "vaultblob_close")
		purego.RegisterLibFunc(&vaultPutFile, handle, "vaultblob_put_file")
		purego.RegisterLibFunc(&vaultReadFile, handle, "vaultblob_read_file")
		purego.RegisterLibFunc(&vaultFileSize, handle, "vaultblob_file_size")
		purego.RegisterLibFunc(&vaultBlobIDs, handle, "vaultblob_blob_ids")
		purego.RegisterLibFunc(&vaultFreeString, handle, "vaultblob_free_string")
		purego.RegisterLibFunc(&vaultFreeStringArray, handle, "vaultblob_free_string_array")
		purego.RegisterLibFunc(&vaultFreeBytes, handle, "vaultblob_free_bytes")

		libLoaded = true
	})
	return libErr
}

var libBinary []byte

func registerBinary(data []byte) {
	libBinary = data
}

func libFilename() string {
	switch runtime.GOOS {
	case "darwin":
		return "libvaultblob.dylib"
	case "linux":
		return "libvaultblob.so"
	case "windows":
		return "vaultblob.dll"
	default:
		return "libvaultblob.so"
	}
}

var (
	vaultOpen func(path, password *byte, maxChunkSize, maxBlobSize uint64, split, stripe, verbose int32, errOut **byte) uintptr

	vaultOpenExisting func(path, password *byte, verbose int32, errOut **byte) uintptr

	vaultClose func(session uintptr)

	vaultPutFile func(session uintptr, data *byte, dataLen int, fileID *byte, outFileID **byte, errOut **byte) int32

	vaultReadFile func(session uintptr, fileID *byte, outLen *int, errOut **byte) uintptr

	vaultFileSize func(session uintptr, fileID *byte, outSize *uint64, errOut **byte) int32

	vaultBlobIDs func(session uintptr, outIDs ***byte, outCount *int, errOut **byte) int32

	vaultFreeString func(s *byte)

	vaultFreeStringArray func(arr **byte, count int)

	vaultFreeBytes func(ptr *byte, len int)
)

func cstr(s string) *byte {
	if s == "" {
		return nil
	}
	b := append([]byte(s), 0)
	return &b[0]
}

func cstrFromPtr(p *byte) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	for *(*byte)(end) != 0 {
		end = unsafe.Add(end, 1)
	}
	n := uintptr(end) - uintptr(unsafe.Pointer(p))
	return string(unsafe.Slice(p, n))
}
