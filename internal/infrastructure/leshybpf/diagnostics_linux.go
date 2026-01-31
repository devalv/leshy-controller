//go:build linux

package leshybpf

import (
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

// RunDiagnostics — тяжелая диагностика: bpftool prog/map list + сравнение map_ids + проверка pinned путей.
// Запускать только при Debug.
func RunDiagnostics(opts DiagnosticsOptions) { //nolint
	log.Debug().Msg("running eBPF diagnostics (debug mode)")

	if opts.Program == "" {
		opts.Program = ProgramName
	}

	if opts.Iface != "" {
		runTCShow(opts.Iface)
	}

	// 1) Программа и её map_ids
	progLine, mapIDs := bpftoolFindProgramMapIDs(opts.Program)
	if progLine != "" {
		log.Debug().Msgf("bpftool: program line: %s", progLine)
	}
	if mapIDs != "" {
		log.Debug().Msgf("bpftool: program map_ids: %s", mapIDs)
	}

	// 2) Список карт и выделение “интересных” id
	mapList := bpftoolMapList()
	if len(mapList) == 0 {
		log.Warn().Msg("bpftool: map list is empty or unavailable")

		return
	}

	// pinned map IDs по именам
	pinnedIDs := map[string]string{} // mapName -> id
	for _, name := range opts.MapNames {
		if name == "" {
			continue
		}
		id := findMapIDByName(mapList, name)
		if id != "" {
			pinnedIDs[name] = id
			log.Debug().Msgf("bpftool: map %s id=%s", name, id)
		}
	}

	// 3) Проверяем, что pinned файлы реально существуют на FS
	checkPinnedPaths(opts.PinPath, opts.MapNames)

	// 4) Сравнение: есть ли pinned map IDs среди program map_ids
	if mapIDs != "" {
		for name, id := range pinnedIDs {
			if strings.Contains(mapIDs, id) {
				log.Info().Msgf("✓ program map_ids contains pinned map %s (id=%s)", name, id)
			} else {
				log.Warn().Msgf("⚠ program map_ids does NOT contain pinned map %s (id=%s). map_ids=%s", name, id, mapIDs)
			}
		}
	}
}

func runTCShow(iface string) {
	cmd := exec.Command("tc", "filter", "show", "dev", iface, "ingress") //nolint:noctx
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug().Err(err).Msg("tc filter show failed")

		return
	}

	s := strings.TrimSpace(string(out))
	if s == "" {
		log.Debug().Msg("tc filter show: empty output")

		return
	}

	if strings.Contains(s, ProgramName) {
		log.Info().Msgf("✓ tc filter show contains %s on %s ingress", ProgramName, iface)
	} else {
		log.Warn().Msgf("⚠ tc filter show does not contain %s on %s ingress", ProgramName, iface)
	}

	log.Debug().Msgf("tc output:\n%s", s)
}

// bpftoolFindProgramMapIDs ищет первую строку программы (по подстроке имени) и вытаскивает map_ids (если есть).
func bpftoolFindProgramMapIDs(programName string) (progLine string, mapIDs string) {
	cmd := exec.Command("bpftool", "prog", "list") //nolint:noctx
	out, err := cmd.Output()
	if err != nil {
		log.Debug().Err(err).Msg("bpftool prog list failed")

		return "", ""
	}

	lines := strings.Split(string(out), "\n")
	for i := range lines {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.Contains(line, programName) {
			progLine = line

			// Ищем map_ids в следующих строках (может быть не сразу следующая)
			for j := i + 1; j < len(lines) && j < i+15; j++ {
				l2 := strings.TrimSpace(lines[j])
				if strings.Contains(l2, "map_ids") {
					mapIDs = extractMapIDs(l2)

					return progLine, mapIDs
				}
				// иногда map_ids может быть в той же строке
				if strings.Contains(line, "map_ids") {
					mapIDs = extractMapIDs(line)

					return progLine, mapIDs
				}
			}

			return progLine, mapIDs
		}
	}

	log.Warn().Msgf("bpftool: program %q not found in prog list", programName)

	return "", ""
}

func extractMapIDs(s string) string {
	// ожидаем фрагмент: "... map_ids 31,32,33,29"
	idx := strings.Index(s, "map_ids")
	if idx < 0 {
		return ""
	}
	part := strings.TrimSpace(s[idx+len("map_ids"):])
	// cut at first space
	if sp := strings.Index(part, " "); sp >= 0 {
		part = part[:sp]
	}
	part = strings.Trim(part, ",")

	return part
}

func bpftoolMapList() []string {
	cmd := exec.Command("bpftool", "map", "list") //nolint:noctx
	out, err := cmd.Output()
	if err != nil {
		log.Debug().Err(err).Msg("bpftool map list failed")

		return nil
	}

	lines := strings.Split(string(out), "\n")
	var res []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			res = append(res, l)
		}
	}

	return res
}

// findMapIDByName пытается найти map id по имени карты в строках `bpftool map list`.
// В bpftool формат обычно: "29: hash  name l4_guarded_ports  flags ...".
func findMapIDByName(mapList []string, mapName string) string {
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

		return id
	}

	return ""
}

func checkPinnedPaths(pinPath string, mapNames []string) {
	if pinPath == "" {
		return
	}

	// pinned program
	progPath := fmt.Sprintf("%s/%s", pinPath, PinnedProgRel)
	if _, err := os.Stat(progPath); err == nil {
		log.Info().Msgf("✓ pinned program exists: %s", progPath)
	} else {
		log.Warn().Msgf("⚠ pinned program not found: %s", progPath)
	}

	for _, name := range mapNames {
		if name == "" {
			continue
		}
		p := fmt.Sprintf("%s/%s", pinPath, name)
		if _, err := os.Stat(p); err == nil {
			log.Info().Msgf("✓ pinned map exists: %s", p)
		} else {
			log.Warn().Msgf("⚠ pinned map not found: %s", p)
		}
	}
}
