package dns

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Record struct {
	Domain     string
	TTL        int
	RecordType string
	Target     string
}

func ParseRootZoneFile(r io.Reader) ([]Record, error) {
	var records []Record
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)

		record := Record{
			Domain:     fields[0],
			TTL:        parseInt(fields[1]),
			RecordType: fields[2],
			Target:     fields[3],
		}

		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
