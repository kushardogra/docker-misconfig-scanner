package parser

import (
	"bufio"
	"os"
	"strings"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func ParseDockerfile(path string) ([]types.Directive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var directives []types.Directive
	sc := bufio.NewScanner(f)
	lineNum := 0
	var pending string

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if pending != "" {
			line = strings.TrimSuffix(pending, "\\") + " " + line
		}

		if strings.HasSuffix(line, "\\") {
			pending = line
			continue
		}
		pending = ""

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		args := ""
		if len(parts) > 1 {
			args = strings.Join(parts[1:], " ")
		}

		directives = append(directives, types.Directive{
			Instruction: strings.ToUpper(parts[0]),
			Args:        args,
			Line:        lineNum,
		})
	}

	return directives, sc.Err()
}
