package clashapi

import (
	"bytes"
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// diffOptions compares two inbound/endpoint entries and reports whether they
// differ at all, and whether the only difference is the named field.
//
// The comparison goes through JSON rather than reflection on the typed options
// because every protocol has its own options struct: marshalling an entry
// yields one flat object (type/tag plus the protocol's own fields), so dropping
// one key and comparing the rest works uniformly for all of them. //H
// Marshalled through a POINTER on purpose: option.Inbound/Endpoint keep the
// protocol's own settings in an `Options any` field tagged `json:"-"`, and the
// only thing that folds them into the output is MarshalJSONContext, which is
// declared on the pointer receiver. Passing a value silently yields just
// {"type","tag"} — making every entry compare equal and the whole diff a
// no-op. //H
func diffOptions[T any](ctx context.Context, have, want T, field string) (changed bool, fieldOnly bool, err error) {
	haveJSON, err := json.MarshalContext(ctx, &have)
	if err != nil {
		return false, false, E.Cause(err, "marshal current options")
	}
	wantJSON, err := json.MarshalContext(ctx, &want)
	if err != nil {
		return false, false, E.Cause(err, "marshal desired options")
	}
	if bytes.Equal(haveJSON, wantJSON) {
		return false, false, nil
	}

	haveRest, err := objectWithout(haveJSON, field)
	if err != nil {
		return true, false, nil //nolint:nilerr // not an object: treat as a full change
	}
	wantRest, err := objectWithout(wantJSON, field)
	if err != nil {
		return true, false, nil //nolint:nilerr
	}
	return true, bytes.Equal(haveRest, wantRest), nil
}

// objectWithout re-encodes a JSON object with one key removed. Keys are sorted
// by encoding/json's map marshalling, so two objects differing only in key
// order still compare equal. //H
func objectWithout(data []byte, field string) ([]byte, error) {
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	delete(object, field)
	return json.Marshal(object)
}
