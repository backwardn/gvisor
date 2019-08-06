// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"gvisor.dev/gvisor/test/runtimes/common"
)

func touch(t *testing.T, name string) {
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSearch(t *testing.T) {
	td, err := ioutil.TempDir("", "walktest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	// Creating various files similar to the test filter regex.
	touch(t, filepath.Join(td, "test-foo.tc"))
	touch(t, filepath.Join(td, "test-bar.tc"))
	touch(t, filepath.Join(td, "test-sam.tc"))
	touch(t, filepath.Join(td, "Test-que.tc"))
	touch(t, filepath.Join(td, "test-brett"))
	touch(t, filepath.Join(td, "test--abc.tc"))
	touch(t, filepath.Join(td, "test---xyz.tc"))
	touch(t, filepath.Join(td, "test-bool.TC"))
	touch(t, filepath.Join(td, "--test-brett.tc"))
	touch(t, filepath.Join(td, " test-pew.tc"))

	// Create files within a single directory.
	dir := filepath.Join(td, "dir")
	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(dir, "test_baz.tc"))
	touch(t, filepath.Join(dir, "testsnap.tc"))
	touch(t, filepath.Join(dir, "test-luk.tc"))

	// Create two empty directories that should be ignored.
	if err := os.MkdirAll(filepath.Join(dir, "emp"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "zee"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create nested directories some with files and some without.
	dip := filepath.Join(dir, "dip")
	if err := os.MkdirAll(filepath.Join(dir, "dip"), 0755); err != nil {
		t.Fatal(err)
	}
	diz := filepath.Join(dip, "diz")
	if err := os.MkdirAll(filepath.Join(dip, "diz"), 0755); err != nil {
		t.Fatal(err)
	}
	goog := filepath.Join(diz, "goog")
	if err := os.MkdirAll(filepath.Join(diz, "goog"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(goog, "test-pack.tc"))
	if err := os.MkdirAll(filepath.Join(dir, "alpha"), 0755); err != nil {
		t.Fatal(err)
	}
	wobble := filepath.Join(diz, "wobble")
	if err := os.MkdirAll(filepath.Join(diz, "wobble"), 0755); err != nil {
		t.Fatal(err)
	}
	thud := filepath.Join(wobble, "thud")
	if err := os.MkdirAll(filepath.Join(wobble, "thud"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(thud, "test-cas.e"))
	touch(t, filepath.Join(thud, "test-cas.tc"))

	testFilter := regexp.MustCompile(`^test-[^-].+\.tc$`)
	got, err := common.Search(td, testFilter)
	if err != nil {
		t.Errorf("Search error: %v", err)
	}
	want := []string{
		"dir/dip/diz/goog/test-pack.tc",
		"dir/dip/diz/wobble/thud/test-cas.tc",
		"dir/test-luk.tc",
		"test-bar.tc",
		"test-foo.tc",
		"test-sam.tc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Found %#v; want %#v", got, want)
	}
}
