package crypt

// Tomb represents an encrypted file with its name and path.
type Tomb struct {
	name string
	path string
}

// NewTomb creates a new Tomb with the given name and path.
func NewTomb(name, path string) (*Tomb, error) {
	if name == "" {
		return nil, ErrEmptyTombName
	}

	if path == "" {
		return nil, ErrEmptyTombPath
	}

	return &Tomb{
		name: name,
		path: path,
	}, nil
}

// Name returns the name of the tomb.
func (t *Tomb) Name() string {
	return t.name
}

// Path returns the path of the tomb.
func (t *Tomb) Path() string {
	return t.path
}
