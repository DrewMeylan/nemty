// SaveHostsToJSON writes discovered hosts to a JSON file
package serialization

import (
	"encoding/json"
	"fmt"
	"os"

	. "github.com/DrewMeylan/nemty/discovery/LessStolenShit/nemty/"
)

func SaveHostsToJSON(hosts []HostInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(hosts)
}
