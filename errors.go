package gope

import "errors"

var (
	ErrInvalidAddress      = errors.New("gope: invalid or unreadable address")
	ErrInvalidPE           = errors.New("gope: invalid or unsupported PE image")
	ErrNotFound            = errors.New("gope: export not found")
	ErrForwardedExport     = errors.New("gope: forwarded export requires explicit resolution")
	ErrUnsupportedPlatform = errors.New("gope: unsupported platform")
	ErrTooManyArguments    = errors.New("gope: too many call arguments")
	ErrInvalidLimit        = errors.New("gope: invalid read limit")
)
