package parse

import "os"

func openFixture(path string) (*os.File, error) {
	return os.Open(path)
}
