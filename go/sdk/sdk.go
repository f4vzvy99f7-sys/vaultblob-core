package vaultblob

import (
	"errors"
	"unsafe"
)

type Options struct {
	MaxChunkSize uint64
	MaxBlobSize  uint64
	SplitFiles   bool
	StripeChunks bool
	Verbose      bool
}

type Session struct {
	handle unsafe.Pointer
}

func Open(dir, password string, opts *Options) (*Session, error) {
	if err := ensureLib(); err != nil {
		return nil, err
	}

	maxChunk := uint64(4 * 1024 * 1024)
	maxBlob := uint64(1024 * 1024 * 1024)
	split := int32(0)
	stripe := int32(0)
	verbose := int32(0)

	if opts != nil {
		if opts.MaxChunkSize != 0 {
			maxChunk = opts.MaxChunkSize
		}
		if opts.MaxBlobSize != 0 {
			maxBlob = opts.MaxBlobSize
		}
		if opts.SplitFiles {
			split = 1
		}
		if opts.StripeChunks {
			stripe = 1
		}
		if opts.Verbose {
			verbose = 1
		}
	}

	var errPtr *byte
	handle := vaultOpen(cstr(dir), cstr(password), maxChunk, maxBlob, split, stripe, verbose, &errPtr)
	if handle == 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return nil, errors.New(msg)
	}

	return &Session{handle: unsafe.Pointer(handle)}, nil
}

func OpenExisting(dir, password string) (*Session, error) {
	if err := ensureLib(); err != nil {
		return nil, err
	}

	var errPtr *byte
	handle := vaultOpenExisting(cstr(dir), cstr(password), 0, &errPtr)
	if handle == 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return nil, errors.New(msg)
	}

	return &Session{handle: unsafe.Pointer(handle)}, nil
}

func (s *Session) Close() {
	if s.handle != nil {
		vaultClose(uintptr(s.handle))
		s.handle = nil
	}
}

func (s *Session) PutFile(data []byte) (string, error) {
	return s.PutFileWithID(data, "")
}

func (s *Session) PutFileWithID(data []byte, fileID string) (string, error) {
	if s.handle == nil {
		return "", errors.New("vaultblob: session closed")
	}

	var fileIDPtr *byte
	if fileID != "" {
		fileIDPtr = cstr(fileID)
	}

	var outPtr *byte
	var errPtr *byte

	result := vaultPutFile(
		uintptr(s.handle),
		&data[0],
		len(data),
		fileIDPtr,
		&outPtr,
		&errPtr,
	)

	if result != 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return "", errors.New(msg)
	}

	id := cstrFromPtr(outPtr)
	vaultFreeString(outPtr)
	return id, nil
}

func (s *Session) ReadFile(fileID string) ([]byte, error) {
	if s.handle == nil {
		return nil, errors.New("vaultblob: session closed")
	}

	var outLen int
	var errPtr *byte

	p := vaultReadFile(uintptr(s.handle), cstr(fileID), &outLen, &errPtr)
	if p == 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return nil, errors.New(msg)
	}

	data := make([]byte, outLen)
	slice := unsafe.Slice((*byte)(unsafe.Pointer(p)), outLen)
	copy(data, slice)
	vaultFreeBytes((*byte)(unsafe.Pointer(p)), outLen)
	return data, nil
}

func (s *Session) FileSize(fileID string) (uint64, error) {
	if s.handle == nil {
		return 0, errors.New("vaultblob: session closed")
	}

	var size uint64
	var errPtr *byte

	result := vaultFileSize(uintptr(s.handle), cstr(fileID), &size, &errPtr)
	if result != 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return 0, errors.New(msg)
	}

	return size, nil
}

func (s *Session) BlobIDs() ([]string, error) {
	if s.handle == nil {
		return nil, errors.New("vaultblob: session closed")
	}

	var outPtr **byte
	var outCount int
	var errPtr *byte

	result := vaultBlobIDs(uintptr(s.handle), &outPtr, &outCount, &errPtr)
	if result != 0 {
		msg := cstrFromPtr(errPtr)
		vaultFreeString(errPtr)
		return nil, errors.New(msg)
	}

	ids := make([]string, outCount)
	for i := 0; i < outCount; i++ {
		// each element is *byte
		p := *(**byte)(unsafe.Add(unsafe.Pointer(outPtr), uintptr(i)*unsafe.Sizeof(outPtr)))
		ids[i] = cstrFromPtr(p)
	}

	vaultFreeStringArray(outPtr, outCount)
	return ids, nil
}
