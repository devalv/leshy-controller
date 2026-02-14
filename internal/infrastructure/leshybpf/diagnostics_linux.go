//go:build linux

package leshybpf

import (
	"context"
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
func RunDiagnostics(ctx context.Context, opts DiagnosticsOptions) error {
	log.Debug().Msg("running eBPF diagnostics (debug mode)")

	if opts.Program == "" {
		opts.Program = ProgramName
	}

	if opts.Iface != "" {
		if err := runTCShow(ctx, opts.Iface); err != nil {
			return fmt.Errorf("runTCShow: %w", err)
		}
	}

	// 1) Программа и её map_ids
	progLine, mapIDs, err := bpftoolFindProgramMapIDs(ctx, opts.Program)
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
	mapList, err := bpftoolMapList(ctx)
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
	if err := checkPinnedPaths(opts.PinPath, opts.MapNames); err != nil {
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

func runTCShow(ctx context.Context, iface string) error {
	out, err := runCmd(ctx, "tc", "filter", "show", "dev", iface, "ingress")
	if err != nil {
		return fmt.Errorf("tc filter show failed: %w: %s", err, string(out))
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
func bpftoolFindProgramMapIDs(ctx context.Context, programName string) (progLine string, mapIDs string, err error) {
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return "", "", nil
	}

	out, err := runCmd(ctx, "bpftool", "prog", "list")
	if err != nil {
		return "", "", fmt.Errorf("failed to list bpf programs with bpftool: %w: %s", err, string(out))
	}

	progLine, mapIDs, err = findProgramInfoInBpftoolOut(out, programName)
	if err != nil {
		return "", "", fmt.Errorf("failed to find program info in bpftool output: %w", err)
	}
	if progLine != "" || mapIDs != "" {
		return progLine, mapIDs, nil
	}

	return "", "", fmt.Errorf("bpftool: program %q not found in prog list", programName)
}

func findProgramInfoInBpftoolOut(out []byte, programName string) (string, string, error) {
	lines := strings.Split(string(out), "\n")

	for i := range lines {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if strings.Contains(line, programName) {
			progLine := line

			// Ищем map_ids, начиная с текущей строки
			mapIDs, err := findMapIDsInLines(lines, i)
			if err != nil {
				return "", "", fmt.Errorf("failed to find map IDs: %w", err)
			}

			return progLine, mapIDs, nil
		}
	}

	return "", "", fmt.Errorf("program %s not found in output", programName)
}

// findMapIDsInLines - ищет map_ids в текущей и следующих строках.
func findMapIDsInLines(lines []string, startIdx int) (string, error) {
	const maxLookahead = 15 // максимальное количество строк для поиска

	// Проверяем текущую строку
	if mapIDs, err := extractMapIDsIfPresent(lines[startIdx]); err != nil {
		return "", fmt.Errorf("extractMapIDs from line %d: %w", startIdx, err)
	} else if mapIDs != "" {
		return mapIDs, nil
	}

	// Ищем в следующих строках (ограничиваем поиск)
	endIdx := min(startIdx+maxLookahead, len(lines))

	for j := startIdx + 1; j < endIdx; j++ {
		line := strings.TrimSpace(lines[j])
		if line == "" {
			continue // пропускаем пустые строки
		}

		if mapIDs, err := extractMapIDsIfPresent(line); err != nil {
			return "", fmt.Errorf("extractMapIDs from line %d: %w", j, err)
		} else if mapIDs != "" {
			return mapIDs, nil
		}
	}

	// Map IDs не найдены - возвращаем пустую строку (это нормально)
	return "", nil
}

// extractMapIDsIfPresent - извлекает map_ids если они есть в строке.
func extractMapIDsIfPresent(line string) (string, error) {
	if strings.Contains(line, "map_ids") {
		return extractMapIDs(line)
	}

	return "", nil
}

func extractMapIDs(s string) (string, error) {
	// ожидаем фрагмент: "... map_ids 31,32,33,29"
	if _, after, found := strings.Cut(s, "map_ids"); found {
		after = strings.TrimSpace(after)
		if trimmed, _, hasSpace := strings.Cut(after, " "); hasSpace {
			after = trimmed
		}

		return strings.Trim(after, ","), nil
	}

	return "", fmt.Errorf("bpftool: map_ids not found in line %q", s)
}

func bpftoolMapList(ctx context.Context) ([]string, error) {
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return nil, nil
	}

	out, err := runCmd(ctx, "bpftool", "map", "list")
	if err != nil {
		return nil, fmt.Errorf("bpftool map list failed: %w: %s", err, string(out))
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

// isBpftoolAvailable проверяет доступность утилиты "bpftool" для вызова.
func isBpftoolAvailable() bool {
	_, err := exec.LookPath("bpftool")

	return err == nil
}
