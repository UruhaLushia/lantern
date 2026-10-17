package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveReplaceAndPrivateLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	for _, value := range []int{1,2} {
		if err := Save(path, struct{ Version int `json:"version"` }{value}); err != nil { t.Fatal(err) }
		var got struct{ Version int `json:"version"` }
		if err := Load(path,&got); err != nil || got.Version != value { t.Fatalf("private state round trip: %+v, %v",got,err) }
	}
	if err := os.WriteFile(path, []byte("{}\n{}\n"),0600); err != nil { t.Fatal(err) }
	var got any
	if err := Load(path,&got); err == nil { t.Fatal("multiple state documents accepted") }
}
