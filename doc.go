// Package gope reads PE32+ images already loaded in the current process.
//
// OpenPE64 validates image headers and exposes independent header snapshots.
// Exports reports named, ordinal-only, and forwarded exports. FindProc and
// FindOrdinal return direct addresses only; forwarders are reported explicitly.
//
// Memory reads and native calls require Windows amd64. The caller must keep
// the module loaded and use the native function's correct ABI and signature.
// This package does not load PE file bytes or resolve forwarded DLLs.
package gope
