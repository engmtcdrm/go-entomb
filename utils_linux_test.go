package entomb

import "testing"

func TestIsValidPath(t *testing.T) {
	validPath := "/valid/path/to/file.txt"
	invalidPath := "/invalid/path/to/fi\000le.txt"

	if isValidPath(validPath) == false {
		t.Errorf("Expected valid path to be valid, but got invalid")
	}

	if isValidPath(invalidPath) == true {
		t.Errorf("Expected invalid path to be invalid, but got valid")
	}
}

func TestIsInvalidPath(t *testing.T) {
	validPath := "/valid/path/to/file.txt"
	invalidPath := "/invalid/path/to/fi\000le.txt"

	if isInvalidPath(validPath) == true {
		t.Errorf("Expected valid path to be valid, but got invalid")
	}

	if isInvalidPath(invalidPath) == false {
		t.Errorf("Expected invalid path to be invalid, but got valid")
	}
}
