package leshybpf

import "github.com/cilium/ebpf"

var (
	// bpfCollection хранит загруженную BPF коллекцию, чтобы она не была закрыта.
	// Позже можно заменить на struct Manager и держать ссылку в bootstrap.
	_             = bpfCollection
	bpfCollection *ebpf.Collection //nolint:gochecknoglobals
)
