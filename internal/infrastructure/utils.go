package infrastructure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/devalv/leshy-controller/internal/domain"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

const (
	PendingSrcMapName   = "l4_pending_src"
	StatsMapName        = "l4_stats"
	ActiveFlowsMapName  = "l4_active_flows"
	GuardedPortsMapName = "l4_guarded_ports"
	LogsMapName         = "l4_logs"
)

var (
	// bpfCollection хранит загруженную BPF коллекцию, чтобы она не была закрыта.
	_             = bpfCollection
	bpfCollection *ebpf.Collection //nolint:gochecknoglobals
)

// HostToNetworkPort converts port from host to network byte order.
func HostToNetworkPort(port uint16) uint16 {
	return hostToNetworkPort(port)
}

// hostToNetworkPort converts port from host to network byte order.
func hostToNetworkPort(port uint16) uint16 {
	return (port >> 8) | (port << 8) //nolint:mnd
}

// networkToHostPort converts port from network to host byte order.
func networkToHostPort(port uint16) uint16 {
	return (port >> 8) | (port << 8) //nolint:mnd
}

// GetGuardedPorts returns the list of guarded ports in HOST BYTE ORDER.
func GetGuardedPorts(m *ebpf.Map) []uint16 {
	var ports []uint16
	iter := m.Iterate()
	var key uint16
	var value uint8

	for iter.Next(&key, &value) {
		// Convert from network byte order to host byte order
		portHost := networkToHostPort(key)
		ports = append(ports, portHost)
	}

	return ports
}

// IsPortGuarded checks if a port is in the guarded ports list (uses NETWORK byte order).
func IsPortGuarded(m *ebpf.Map, port uint16) bool {
	// Convert port to network byte order for lookup
	portNetwork := hostToNetworkPort(port)
	var value uint8
	err := m.Lookup(&portNetwork, &value)

	return err == nil
}

// InsertPendingSrcPort inserts an IP+port into the pending map with expiration.
func InsertPendingSrcPort(m *ebpf.Map, ip net.IP, port uint16, window time.Duration) error { //nolint:funlen
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	// Convert port to network byte order for the key
	portNetwork := hostToNetworkPort(port)

	// Create IP+port key
	// ПРОБЛЕМА: cilium/ebpf записывает структуру в том порядке байт, в котором она хранится в памяти Go (little-endian)
	// Но BPF программа ожидает ключ в network byte order (big-endian)
	// РЕШЕНИЕ: используем прямой syscall bpf() для записи ключа в правильном порядке байт

	// Формируем ключ в network byte order (big-endian) как байтовый массив
	keyBytes := make([]byte, 8)                                             //nolint:mnd
	binary.BigEndian.PutUint32(keyBytes[0:4], binary.BigEndian.Uint32(ip4)) // IP в network byte order
	binary.BigEndian.PutUint16(keyBytes[4:6], portNetwork)                  // порт в network byte order
	binary.BigEndian.PutUint16(keyBytes[6:8], 0)                            // pad = 0

	// Calculate expiration in nanoseconds
	expiry := time.Now().Add(window).UnixNano()
	valueBytes := make([]byte, 8)                             //nolint:mnd
	binary.LittleEndian.PutUint64(valueBytes, uint64(expiry)) // #nosec G115 // значение в little-endian (стандарт для BPF)

	log.Info().Msgf("inserting authorization: IP=%s, Port=%d (network: %d), Expires=%s",
		ip, port, portNetwork, time.Now().Add(window).Format(time.RFC3339))
	log.Debug().Msgf("  key bytes in network byte order (big-endian): %x", keyBytes)

	// ВАЖНО: используем прямой syscall bpf() для записи ключа в правильном порядке байт
	// Это обходит cilium/ebpf и записывает ключ напрямую в карту
	mapFD := m.FD()
	if mapFD < 0 {
		return fmt.Errorf("invalid map file descriptor: %d", mapFD)
	}

	// На Linux x86_64 структура выровнена по 8 байт
	type bpfAttrMapUpdateElem struct {
		MapFD uint32
		_     uint32 // padding для выравнивания
		Key   uint64 // pointer to key (8 bytes)
		Value uint64 // pointer to value (8 bytes)
		Flags uint64 // BPF_ANY = 0
	}

	attr := bpfAttrMapUpdateElem{
		MapFD: uint32(mapFD),                                   // #nosec G115
		Key:   uint64(uintptr(unsafe.Pointer(&keyBytes[0]))),   // #nosec G103
		Value: uint64(uintptr(unsafe.Pointer(&valueBytes[0]))), // #nosec G103
		Flags: 0,                                               // BPF_ANY
	}

	// Вызов syscall BPF_MAP_UPDATE_ELEM
	// На Linux x86_64 номер syscall для bpf() = 321
	// Используем unix.Syscall для правильной обработки ошибок
	_, _, errno := unix.Syscall(
		321,                            //nolint:mnd // SYS_BPF на Linux x86_64
		2,                              //nolint:mnd // BPF_MAP_UPDATE_ELEM
		uintptr(unsafe.Pointer(&attr)), // #nosec G103
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		return fmt.Errorf("bpf syscall failed: %w (errno: %w)", errno, errno)
	}

	log.Debug().Msg("  ✓ key written to map via direct bpf() syscall")

	// ДИАГНОСТИКА: читаем ключ обратно через прямой syscall для проверки байтов
	type bpfAttrMapLookupElem struct {
		MapFD uint32
		_     uint32 // padding
		Key   uint64 // pointer to key
		Value uint64 // pointer to value
	}

	readKeyBytes := make([]byte, 8)   //nolint:mnd
	readValueBytes := make([]byte, 8) //nolint:mnd

	readAttr := bpfAttrMapLookupElem{
		MapFD: uint32(mapFD),                                       // #nosec G115
		Key:   uint64(uintptr(unsafe.Pointer(&keyBytes[0]))),       // #nosec G103
		Value: uint64(uintptr(unsafe.Pointer(&readValueBytes[0]))), // #nosec G103
	}

	_, _, readErrno := unix.Syscall(
		321,                                //nolint:mnd // SYSBPF
		1,                                  // BPF_MAP_LOOKUP_ELEM
		uintptr(unsafe.Pointer(&readAttr)), // #nosec G103
		unsafe.Sizeof(readAttr),
	)

	if readErrno == 0 {
		// Сравниваем записанные и прочитанные байты
		copy(readKeyBytes, keyBytes)
		log.Debug().Msgf("  ✓ read back via syscall: key bytes=%x, value bytes=%x", readKeyBytes, readValueBytes)

		// Парсим прочитанные байты как структуру для сравнения с bpftool
		readSaddr := binary.BigEndian.Uint32(readKeyBytes[0:4])
		readDport := binary.BigEndian.Uint16(readKeyBytes[4:6])
		log.Debug().Msgf("  ✓ parsed from bytes: saddr=0x%08X (%d), dport=0x%04X (%d)",
			readSaddr, readSaddr, readDport, readDport)

		// Также парсим как little-endian для сравнения с тем, что показывает bpftool
		readSaddrLE := binary.LittleEndian.Uint32(readKeyBytes[0:4])
		readDportLE := binary.LittleEndian.Uint16(readKeyBytes[4:6])
		log.Debug().Msgf("  ⚠ parsed as little-endian: saddr=0x%08X (%d), dport=0x%04X (%d) [this is what bpftool shows]",
			readSaddrLE, readSaddrLE, readDportLE, readDportLE)
	} else {
		log.Debug().Msgf("  ⚠ WARNING: failed to read back via syscall: errno=%d", readErrno)
	}

	// ДИАГНОСТИКА: также проверяем через cilium/ebpf
	var readValue uint64
	readErr := m.Lookup(keyBytes, &readValue)
	if readErr != nil {
		log.Debug().Msgf("  ⚠ WARNING: failed to read back via cilium/ebpf: %v", readErr)
	} else {
		log.Debug().Msgf("  ✓ verified via cilium/ebpf: key exists, value=%d", readValue)
	}

	return nil
}

// GetBPFStats retrieves statistics from BPF stats map.
func GetBPFStats(m *ebpf.Map) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{"error": "stats map not available"}
	}

	stats := make(map[string]interface{})
	key := uint32(0)

	// Читаем сырые байты из карты
	var rawBytes []byte
	err := m.Lookup(&key, &rawBytes)
	if err != nil {
		stats["error"] = err.Error()

		return stats
	}

	// 10 полей × 8 байт = 80 байт
	if len(rawBytes) >= 80 { //nolint:mnd
		// Читаем все 10 полей структуры
		stats["allowed"] = binary.LittleEndian.Uint64(rawBytes[0:8])
		stats["dropped"] = binary.LittleEndian.Uint64(rawBytes[8:16])
		stats["syn_allowed"] = binary.LittleEndian.Uint64(rawBytes[16:24])
		stats["syn_dropped"] = binary.LittleEndian.Uint64(rawBytes[24:32])
		stats["active_flow_hits"] = binary.LittleEndian.Uint64(rawBytes[32:40])
		stats["pending_promotions"] = binary.LittleEndian.Uint64(rawBytes[40:48])
		stats["pending_expired_cleanups"] = binary.LittleEndian.Uint64(rawBytes[48:56])
		stats["ip_port_auth_hits"] = binary.LittleEndian.Uint64(rawBytes[56:64])
		stats["non_guarded_port_allowed"] = binary.LittleEndian.Uint64(rawBytes[64:72])
		stats["guarded_port_dropped"] = binary.LittleEndian.Uint64(rawBytes[72:80])

		// Calculate percentages
		total := stats["allowed"].(uint64) + stats["dropped"].(uint64) //nolint:forcetypeassert
		if total > 0 {
			stats["allow_rate_percent"] = float64(stats["allowed"].(uint64)) / float64(total) * 100 //nolint
			stats["drop_rate_percent"] = float64(stats["dropped"].(uint64)) / float64(total) * 100  //nolint
		}
	} else {
		stats["error"] = fmt.Sprintf("invalid data size: expected >=80 bytes, got %d", len(rawBytes))
	}

	return stats
}

// setGuardedPorts sets the list of guarded ports in NETWORK BYTE ORDER.
func setGuardedPorts(m *ebpf.Map, ports []uint16) error {
	// Clear existing ports
	iter := m.Iterate()
	var key uint16
	var value uint8
	for iter.Next(&key, &value) {
		m.Delete(&key) //nolint
	}

	// Add new ports in NETWORK BYTE ORDER
	for _, port := range ports {
		// Convert port to network byte order
		portNetwork := hostToNetworkPort(port)
		value := uint8(1)
		if err := m.Put(&portNetwork, &value); err != nil {
			return fmt.Errorf("failed to add port %d (network: %d): %w", port, portNetwork, err)
		}
		log.Debug().Msgf("added guarded port: %d (network byte order: %d)", port, portNetwork)
	}

	return nil
}

// InitializeGuardedPorts initializes guarded ports from port range.
func InitializeGuardedPorts(portsRange string, m *ebpf.Map) {
	ports := parsePortRange(portsRange)
	if err := setGuardedPorts(m, ports); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize guarded ports")
	}

	log.Debug().Msgf("Guarded %d ports: %v", len(ports), portsRange)
}

// parsePortRange parses port range in "start-end" format.
func parsePortRange(portsRange string) []uint16 {
	parts := strings.Split(portsRange, "-")
	if len(parts) != 2 { //nolint:mnd
		// Не должно происходить после валидации, но на всякий случай
		log.Error().Msgf("invalid port range format: %s", portsRange)

		return nil
	}

	// ошибок быть не должно после валидации
	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		log.Error().Err(err).Msgf("invalid start port: %s", parts[0])

		return nil
	}

	end, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		log.Error().Err(err).Msgf("invalid end port: %s", parts[1])

		return nil
	}

	var ports []uint16
	for port := start; port <= end; port++ {
		ports = append(ports, uint16(port))
	}

	return ports
}

// AttachBPFWithTC загружает и прикрепляет BPF программу к TC.
// Возвращает карты из коллекции, чтобы контроллер использовал те же карты, что и программа.
// TODO: принимать структуру?
func AttachBPFWithTC(iface, BPFPinPath, BPFProgramPath string, pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map) error { //nolint
	// ВАЖНО: Удаляем старые TC фильтры и старые закрепленные карты перед загрузкой новой программы
	// Это гарантирует, что новая программа не будет использовать старые карты
	log.Info().Msgf("cleaning up old TC filters and maps for interface %s", iface)
	cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact") //nolint:noctx
	cmd.Run()                                                         //nolint // игнорируем ошибку, если qdisc не существует

	// Удаляем старую закрепленную программу, чтобы гарантировать использование новых карт
	oldProgPath := BPFPinPath + "/l4_filter"
	if err := os.Remove(oldProgPath); err == nil {
		log.Info().Msgf("removed old pinned program: %s", oldProgPath)
	}

	// Удаляем старые закрепленные карты, чтобы гарантировать использование новых
	oldMaps := []string{
		PendingSrcMapName,
		GuardedPortsMapName,
		StatsMapName,
		ActiveFlowsMapName,
		LogsMapName,
	}
	for _, mapName := range oldMaps {
		mapPath := fmt.Sprintf("%s/%s", BPFPinPath, mapName)
		if err := os.Remove(mapPath); err == nil {
			log.Info().Msgf("removed old pinned map: %s", mapPath)
		}
	}

	// Также удаляем все старые BPF программы и карты через bpftool
	// Это гарантирует, что не останется старых ссылок
	log.Info().Msg("cleaning up old BPF programs and maps via bpftool...")
	cmd = exec.Command("bpftool", "prog", "list") //nolint:noctx
	progListOutput, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(progListOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, "l4_filter") {
				// Извлекаем ID программы
				parts := strings.Fields(line)
				if len(parts) > 0 {
					progID := strings.TrimSuffix(parts[0], ":")
					log.Info().Msgf("removing old BPF program ID: %s", progID)
					exec.Command("bpftool", "prog", "delete", "id", progID).Run() //nolint
				}
			}
		}
	}

	// Загружаем спецификацию BPF программы
	spec, err := ebpf.LoadCollectionSpec(BPFProgramPath)
	if err != nil {
		return fmt.Errorf("loading BPF collection spec: %w", err)
	}

	// Устанавливаем PinPath для автоматического закрепления карт
	pinPath := BPFPinPath
	spec.Maps[PendingSrcMapName].Pinning = ebpf.PinByName
	spec.Maps[ActiveFlowsMapName].Pinning = ebpf.PinByName
	spec.Maps[StatsMapName].Pinning = ebpf.PinByName
	spec.Maps[GuardedPortsMapName].Pinning = ebpf.PinByName
	if spec.Maps[LogsMapName] != nil {
		spec.Maps[LogsMapName].Pinning = ebpf.PinByName
	}

	// Опции для закрепления карт
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}

	// ВАЖНО: При использовании PinByName, если карты уже закреплены,
	// ebpf переиспользует существующие карты. Это гарантирует, что программа
	// использует те же карты, что и контроллер.
	// Загружаем коллекцию с опциями
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	// Сохраняем коллекцию в глобальной переменной, чтобы она не была закрыта
	bpfCollection = coll

	// Получаем карты из коллекции - это гарантирует, что контроллер использует те же карты, что и программа
	*pendingMap = coll.Maps[PendingSrcMapName]
	*guardedPortsMap = coll.Maps[GuardedPortsMapName]
	*statsMap = coll.Maps[StatsMapName]
	*activeFlowsMap = coll.Maps[ActiveFlowsMapName]

	if *pendingMap == nil || *guardedPortsMap == nil || *statsMap == nil || *activeFlowsMap == nil {
		coll.Close()

		return errors.New("failed to get maps from collection")
	}

	// Получаем программу
	prog := coll.Programs["l4_filter"]
	if prog == nil {
		coll.Close()
		bpfCollection = nil

		return errors.New("l4_filter program not found")
	}

	// Закрепляем программу
	progPinFile := pinPath + "/l4_filter"
	if err := prog.Pin(progPinFile); err != nil {
		if !os.IsExist(err) {
			log.Warn().Err(err).Msg("failed to pin program")
		} else {
			log.Info().Msgf("program already pinned at %s", progPinFile)
		}
	} else {
		log.Info().Msgf("program pinned at %s", progPinFile)
	}

	// Убедимся что есть clsact qdisc
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface, "clsact") //nolint:noctx
	cmd.Run()                                                        //nolint // игнорируем ошибку, если уже существует

	// Прикрепляем программу к ingress через tc
	// ВАЖНО: используем ТОЛЬКО pinned программу, чтобы она использовала закрепленные карты
	// Использование obj файла напрямую создаст новые карты, не связанные с закрепленными
	cmd = exec.Command("tc", "filter", "replace", "dev", iface, "ingress", "prio", "1", "handle", "1", "bpf", "da", "pinned", progPinFile) //nolint
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		coll.Close()

		return fmt.Errorf("attaching TC filter with pinned program: %w (program must be pinned to use pinned maps)", err)
	}

	log.Debug().Msgf("BPF program loaded and attached to %s ingress (FD: %d)", iface, prog.FD())
	log.Info().Msgf("BPF maps pinned in %s", pinPath)

	// Проверяем, какие карты использует загруженная программа через bpftool
	// Это поможет убедиться, что программа использует правильные карты
	log.Debug().Msg("  checking which maps the loaded program uses...")
	cmd = exec.Command("bpftool", "prog", "list") //nolint:noctx
	var output []byte
	output, err = cmd.Output()
	if err == nil { //nolint:nestif
		// Ищем программу l4_filter в выводе
		lines := strings.Split(string(output), "\n")
		foundProgram := false
		for i, line := range lines {
			if strings.Contains(line, "l4_filter") {
				foundProgram = true
				log.Debug().Msgf("  found l4_filter program: %s", strings.TrimSpace(line))
				// Ищем map_ids в следующих строках (может быть через несколько строк)
				for j := i + 1; j < len(lines) && j < i+10; j++ {
					if strings.Contains(lines[j], "map_ids") {
						log.Debug().Msgf("  program map_ids line: %s", strings.TrimSpace(lines[j]))

						// Парсим map_ids и проверяем, какие карты использует программа
						mapIdsLine := strings.TrimSpace(lines[j])
						// Ищем "map_ids" и извлекаем числа после него
						// Формат: "xlated 4344B  jited 2306B  memlock 8192B  map_ids 31,32,33,29,30"
						mapIdsIndex := strings.Index(mapIdsLine, "map_ids")
						if mapIdsIndex >= 0 {
							// Берем все после "map_ids "
							mapIdsPart := strings.TrimSpace(mapIdsLine[mapIdsIndex+7:])
							// Убираем все после первого пробела или конца строки
							if spaceIndex := strings.Index(mapIdsPart, " "); spaceIndex >= 0 {
								mapIdsPart = mapIdsPart[:spaceIndex]
							}
							mapIdsStr := mapIdsPart
							log.Debug().Msgf("  program uses map IDs: %s", mapIdsStr)

							// Проверяем, какие карты соответствуют этим ID
							cmd = exec.Command("bpftool", "map", "list") //nolint:noctx
							mapListOutput, err := cmd.Output()
							if err == nil {
								mapListLines := strings.Split(string(mapListOutput), "\n")
								programGuardedPortsID := ""
								programPendingSrcID := ""
								for _, mapLine := range mapListLines {
									for _, mapId := range strings.Split(mapIdsStr, ",") {
										mapId = strings.TrimSpace(mapId)
										if strings.HasPrefix(mapLine, mapId+":") {
											if strings.Contains(mapLine, "l4_") {
												log.Debug().Msgf("    map ID %s: %s", mapId, strings.TrimSpace(mapLine))
												if strings.Contains(mapLine, GuardedPortsMapName) {
													programGuardedPortsID = mapId
												}
												if strings.Contains(mapLine, PendingSrcMapName) {
													programPendingSrcID = mapId
												}
											}
										}
									}
								}

								// Сохраняем ID для сравнения позже (в глобальной переменной или передадим через замыкание)
								// Пока просто выводим
								if programGuardedPortsID != "" {
									log.Debug().Msgf("  program uses guarded_ports map ID: %s", programGuardedPortsID)
								}
								if programPendingSrcID != "" {
									log.Debug().Msgf("  program uses pending_src map ID: %s", programPendingSrcID)
								}

								// Сохраняем для сравнения ниже
								programGuardedPortsIDSaved := programGuardedPortsID
								programPendingSrcIDSaved := programPendingSrcID

								// Сравниваем после получения pinned IDs (будет сделано ниже)
								_ = programGuardedPortsIDSaved
								_ = programPendingSrcIDSaved
							}
						}

						break
					}
				}
			}
		}
		if !foundProgram {
			log.Warn().Msg("  ⚠ WARNING: l4_filter program not found in bpftool prog list")
		}
	} else {
		log.Warn().Err(err).Msgf("  ⚠ WARNING: failed to run bpftool prog list")
	}

	// Также проверяем ID закрепленных карт и сравниваем с теми, что использует программа
	log.Debug().Msg("  checking pinned map IDs and comparing with program:")
	cmd = exec.Command("bpftool", "map", "list") //nolint:noctx
	output, err = cmd.Output()
	if err == nil { //nolint:nestif
		lines := strings.Split(string(output), "\n")
		pinnedGuardedPortsID := ""
		pinnedPendingSrcID := ""
		for _, line := range lines {
			if strings.Contains(line, GuardedPortsMapName) {
				log.Debug().Msgf("    guarded_ports map: %s", strings.TrimSpace(line))
				// Извлекаем ID (первое число до :)
				parts := strings.Fields(line)
				if len(parts) > 0 {
					pinnedGuardedPortsID = strings.TrimSuffix(parts[0], ":")
					log.Debug().Msgf("      pinned guarded_ports map ID: %s", pinnedGuardedPortsID)
				}
			}
			if strings.Contains(line, PendingSrcMapName) {
				log.Debug().Msgf("    pending_src map: %s", strings.TrimSpace(line))
				parts := strings.Fields(line)
				if len(parts) > 0 {
					pinnedPendingSrcID = strings.TrimSuffix(parts[0], ":")
					log.Debug().Msgf("      pinned pending_src map ID: %s", pinnedPendingSrcID)
				}
			}
		}

		// Сравниваем ID закрепленных карт с теми, что использует программа
		// Получаем ID карт, которые использует программа, из предыдущего блока
		// (они уже были выведены в лог выше)

		// Проверяем, использует ли программа те же карты
		// Получаем ID карт, которые использует программа, из предыдущего блока
		cmd = exec.Command("bpftool", "prog", "list") //nolint:noctx
		progOutput, err := cmd.Output()
		if err == nil {
			progLines := strings.Split(string(progOutput), "\n")
			for i, line := range progLines {
				if strings.Contains(line, "l4_filter") && i+1 < len(progLines) {
					nextLine := progLines[i+1]
					if strings.Contains(nextLine, "map_ids") {
						// Извлекаем map_ids из строки
						mapIdsIndex := strings.Index(nextLine, "map_ids")
						if mapIdsIndex >= 0 {
							mapIdsPart := strings.TrimSpace(nextLine[mapIdsIndex+7:])
							if spaceIndex := strings.Index(mapIdsPart, " "); spaceIndex >= 0 {
								mapIdsPart = mapIdsPart[:spaceIndex]
							}
							mapIdsStr := mapIdsPart

							// Получаем ID карт, которые использует программа
							cmd = exec.Command("bpftool", "map", "list") //nolint:noctx
							mapListOutput, err := cmd.Output()
							if err == nil {
								mapListLines := strings.Split(string(mapListOutput), "\n")
								programGuardedPortsID := ""
								programPendingSrcID := ""
								for _, mapLine := range mapListLines {
									for _, mapId := range strings.Split(mapIdsStr, ",") {
										mapId = strings.TrimSpace(mapId)
										if strings.HasPrefix(mapLine, mapId+":") {
											if strings.Contains(mapLine, GuardedPortsMapName) {
												programGuardedPortsID = mapId
											}
											if strings.Contains(mapLine, PendingSrcMapName) {
												programPendingSrcID = mapId
											}
										}
									}
								}

								// Сравниваем с закрепленными картами
								if pinnedGuardedPortsID != "" {
									if programGuardedPortsID == pinnedGuardedPortsID {
										log.Info().Msgf("  ✓ program uses correct guarded_ports map (ID: %s)", programGuardedPortsID)
									} else {
										log.Warn().Msgf("  ⚠ WARNING: program uses different guarded_ports map!")
										log.Warn().Msgf("    program map ID: %s, pinned map ID: %s", programGuardedPortsID, pinnedGuardedPortsID)
									}
								}
								if pinnedPendingSrcID != "" {
									if programPendingSrcID == pinnedPendingSrcID {
										log.Info().Msgf("  ✓ program uses correct pending_src map (ID: %s)", programPendingSrcID)
									} else {
										log.Warn().Msgf("  ⚠ WARNING: program uses different pending_src map!")
										log.Warn().Msgf("    program map ID: %s, pinned map ID: %s", programPendingSrcID, pinnedPendingSrcID)
									}
								}
							}

							if pinnedGuardedPortsID != "" {
								if strings.Contains(mapIdsStr, pinnedGuardedPortsID) {
									log.Info().Msgf("  ✓ program map_ids contains pinned guarded_ports map ID: %s", pinnedGuardedPortsID)
								} else {
									log.Warn().Msgf("  ⚠ WARNING: program map_ids does NOT contain pinned guarded_ports map ID!")
									log.Warn().Msgf("    pinned map ID: %s, program map_ids: %s", pinnedGuardedPortsID, mapIdsStr)
								}
							}
						}
					}
				}
			}
		}
	}

	// Проверяем, что карты закреплены
	for name := range coll.Maps {
		mapPath := fmt.Sprintf("%s/%s", pinPath, name)
		if _, err := os.Stat(mapPath); err == nil {
			log.Info().Msgf("  ✓ map %s pinned at %s", name, mapPath)
		} else {
			log.Warn().Msgf("  ✗ map %s not pinned at %s", name, mapPath)
		}
	}

	// Проверяем, что pending map доступна для записи
	if pendingMap, ok := coll.Maps[PendingSrcMapName]; ok {
		testKey := domain.IpPortKey{Saddr: 0x01010101, Dport: 0x1234, Pad: 0} //nolint:mnd
		testValue := uint64(time.Now().UnixNano())                            //nolint
		if err := pendingMap.Put(&testKey, &testValue); err != nil {
			log.Warn().Err(err).Msgf("  ⚠ WARNING: failed to write test entry to pending map")
		} else {
			pendingMap.Delete(&testKey) //nolint
			log.Info().Msg("  ✓ pending map is writable")
		}
	}

	// Проверяем прикрепление через tc
	cmd = exec.Command("tc", "filter", "show", "dev", iface, "ingress") //nolint:noctx
	output, err = cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "l4_filter") {
			log.Info().Msgf("  ✓ TC filter found on %s ingress", iface)
		} else {
			log.Warn().Msg("  ⚠ WARNING: TC filter not found in tc output")
			log.Warn().Msgf("  tc output: %s", string(output))
		}
	}

	return nil
}
