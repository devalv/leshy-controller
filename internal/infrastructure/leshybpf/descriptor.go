package leshybpf

import "fmt"

func getMapFDUint32(fd int) (uint32, error) {
	if fd < 0 {
		return 0, fmt.Errorf("invalid map file descriptor: %d", fd)
	}

	// выше выполняется проверка на возможное переполнение
	return uint32(fd), nil // #nosec G115
}
