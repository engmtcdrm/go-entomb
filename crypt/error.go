package crypt

const (
	ErrorPrefix                      = "crypt: "
	ErrorMessageFormat               = "%s: %w"
	ErrorEmptyKeyPath                = ErrorPrefix + "key path is empty"
	ErrorEmptyTombName               = ErrorPrefix + "tomb name is empty"
	ErrorEmptyTombPath               = ErrorPrefix + "tomb path is empty"
	ErrorEmptyTombsPath              = ErrorPrefix + "tombs path is empty"
	ErrorInitializingTombsPath       = ErrorPrefix + "initializing tombs path failed"
	ErrorInvalidTombName             = ErrorPrefix + "invalid tomb name"
	ErrorInvalidTombPath             = ErrorPrefix + "invalid tomb path"
	ErrorInvalidTombsPath            = ErrorPrefix + "invalid tombs path"
	ErrorMakingTombPathFailed        = ErrorPrefix + "making tomb path failed"
	ErrorReadingTombFailed           = ErrorPrefix + "reading tomb failed"
	ErrorWritingTombFailed           = ErrorPrefix + "writing tomb failed"
	ErrorRemovingFileFailed          = ErrorPrefix + "removing file failed"
	ErrorRemovingTombFailed          = ErrorPrefix + "removing tomb failed"
	ErrorEncryptingTombFailed        = ErrorPrefix + "encrypting tomb failed"
	ErrorDecryptingTombFailed        = ErrorPrefix + "decrypting tomb failed"
	ErrorTombsPathIsDirectory        = ErrorPrefix + "tombs path exists but is not a directory"
	ErrorTombNotFound                = ErrorPrefix + "tomb not found"
	ErrorGettingTombsPathFilesFailed = ErrorPrefix + "getting tombs from tombs path failed"
)
