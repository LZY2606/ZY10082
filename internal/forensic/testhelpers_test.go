package forensic

import (
	"encoding/json"
	"io"
)

func writeJSONForTest(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
