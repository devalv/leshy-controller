//go:build linux

package leshybpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

type DiagnosticsOptions struct {
	Iface    string
	PinPath  string
	Program  string
	MapNames []string
}

// RunDiagnostics — для отладки: bpftool prog/map list + сравнение map_ids + проверка pinned путей.
func RunDiagnostics(opts DiagnosticsOptions) error { //nolint
	log.Debug().Msg("running eBPF diagnostics (debug mode)")

	if opts.Program == "" {
		opts.Program = ProgramName
	}

	if opts.Iface != "" {
		err := runTCShow(opts.Iface)
		if err != nil {
			return fmt.Errorf("runTCShow: %w", err)
		}
	}

	// 1) Программа и её map_ids
	progLine, mapIDs, err := bpftoolFindProgramMapIDs(opts.Program)
	if progLine != "" {
		log.Debug().Msgf("bpftool: program line: %s", progLine)
	}
	if mapIDs != "" {
		log.Debug().Msgf("bpftool: program map_ids: %s", mapIDs)
	}
	if err != nil {
		return fmt.Errorf("bpftoolFindProgramMapIDs: %w", err)
	}

	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool not found. extra debug will be disabled.")

		return nil
	}

	// 2) Список карт и выделение “интересных” id
	mapList, err := bpftoolMapList()
	if len(mapList) == 0 {
		return errors.New("bpftool: map list is empty or unavailable")
	}
	if err != nil {
		return fmt.Errorf("bpftool: map list failed: %w", err)
	}

	// pinned map IDs по именам
	pinnedIDs := map[string]string{} // mapName -> id
	for _, name := range opts.MapNames {
		if name == "" {
			continue
		}
		id, err := findMapIDByName(mapList, name)
		if err != nil {
			return fmt.Errorf("findMapIDByName: %w", err)
		}
		if id != "" {
			pinnedIDs[name] = id
			log.Debug().Msgf("bpftool: map %s id=%s", name, id)
		}
	}

	// 3) Проверяем, что pinned файлы реально существуют на FS
	err = checkPinnedPaths(opts.PinPath, opts.MapNames)
	if err != nil {
		return fmt.Errorf("checkPinnedPaths: %w", err)
	}

	// 4) Сравнение: есть ли pinned map IDs среди program map_ids
	if mapIDs != "" {
		for name, id := range pinnedIDs {
			if strings.Contains(mapIDs, id) {
				log.Debug().Msgf("✓ program map_ids contains pinned map %s (id=%s)", name, id)
			} else {
				return fmt.Errorf("⚠ program map_ids does NOT contain pinned map %s (id=%s). map_ids=%s", name, id, mapIDs)
			}
		}
	}

	return nil
}

func runTCShow(iface string) error {
	cmd := exec.Command("tc", "filter", "show", "dev", iface, "ingress") //nolint:noctx
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc filter show failed: %w", err)
	}

	s := strings.TrimSpace(string(out))
	if s == "" {
		return errors.New("tc filter show failed: empty output")
	}

	if strings.Contains(s, ProgramName) {
		log.Debug().Msgf("✓ tc filter show contains %s on %s ingress", ProgramName, iface)
	} else {
		return fmt.Errorf("⚠ tc filter show does not contain %s on %s ingress", ProgramName, iface)
	}

	log.Debug().Msgf("tc output: %s", s)

	return nil
}

// bpftoolFindProgramMapIDs ищет первую строку программы (по подстроке имени) и вытаскивает map_ids (если есть).
func bpftoolFindProgramMapIDs(programName string) (progLine string, mapIDs string, err error) { //nolint:cyclop
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return "", "", nil
	}

	cmd := exec.Command("bpftool", "prog", "list") //nolint:noctx
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to list bpf programs with bpftool: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for i := range lines {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if strings.Contains(line, programName) { //nolint:nestif
			progLine = line

			// Ищем map_ids в следующих строках (может быть не сразу следующая)
			for j := i + 1; j < len(lines) && j < i+15; j++ {
				l2 := strings.TrimSpace(lines[j])
				if strings.Contains(l2, "map_ids") {
					mapIDs, err = extractMapIDs(l2)
					if err != nil {
						return "", "", fmt.Errorf("extractMapIDs: %w", err)
					}

					return progLine, mapIDs, nil
				}
				// иногда map_ids может быть в той же строке
				if strings.Contains(line, "map_ids") {
					mapIDs, err = extractMapIDs(line)
					if err != nil {
						return "", "", fmt.Errorf("extractMapIDs: %w", err)
					}

					return progLine, mapIDs, nil
				}
			}

			return progLine, mapIDs, nil
		}
	}

	return "", "", fmt.Errorf("bpftool: program %q not found in prog list", programName)
}

func extractMapIDs(s string) (string, error) {
	// ожидаем фрагмент: "... map_ids 31,32,33,29"
	idx := strings.Index(s, "map_ids") // TODO: not optimal
	if idx < 0 {
		return "", fmt.Errorf("bpftool: map_ids not found in line %q", s)
	}
	part := strings.TrimSpace(s[idx+len("map_ids"):])

	if sp := strings.Index(part, " "); sp >= 0 {
		part = part[:sp]
	}
	part = strings.Trim(part, ",")

	return part, nil
}

func bpftoolMapList() ([]string, error) {
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return nil, nil
	}
	cmd := exec.Command("bpftool", "map", "list") //nolint:noctx
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bpftool map list failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var res []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			res = append(res, l)
		}
	}

	return res, nil
}

// findMapIDByName пытается найти map id по имени карты в строках `bpftool map list`.
// В bpftool формат обычно: "29: hash  name l4_guarded_ports  flags ...".
func findMapIDByName(mapList []string, mapName string) (string, error) {
	for _, line := range mapList {
		if !strings.Contains(line, mapName) {
			continue
		}
		// id — первое поле до ':'
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := strings.TrimSuffix(fields[0], ":")

		return id, nil
	}

	return "", fmt.Errorf("map %s not found", mapName)
}

func checkPinnedPaths(pinPath string, mapNames []string) error {
	if pinPath == "" {
		return errors.New("pin path is empty")
	}

	// pinned program
	progPath := fmt.Sprintf("%s/%s", pinPath, PinnedProgRel)
	if _, err := os.Stat(progPath); err == nil {
		log.Debug().Msgf("✓ pinned program exists: %s", progPath)
	} else {
		return fmt.Errorf("⚠ pinned program not found: %s", progPath)
	}

	for _, name := range mapNames {
		if name == "" {
			continue
		}
		p := fmt.Sprintf("%s/%s", pinPath, name)
		if _, err := os.Stat(p); err == nil {
			log.Debug().Msgf("✓ pinned map exists: %s", p)
		} else {
			return fmt.Errorf("⚠ pinned map not found: %s", p)
		}
	}

	return nil
}

// isBpftoolAvailable checks if the "bpftool" command is present in the system's PATH.
func isBpftoolAvailable() bool {
	_, err := exec.LookPath("bpftool")

	return err == nil
}
