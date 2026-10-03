package syncapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Call sends one request to the server listening on socketPath and returns
// its response. A response with OK=false is returned as its *Error.
func Call(ctx context.Context, socketPath string, req Request) (Response, error) {
	if _, err := req.Decode(); err != nil {
		return Response{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := WriteMessage(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := ReadMessage(bufio.NewReaderSize(conn, 64<<10), &resp); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, &Error{Code: CodeUnavailable, Message: "reading the response: " + err.Error()}
	}
	if resp.ID != req.ID {
		return Response{}, errors.New("syncapi: response for another request")
	}
	if !resp.OK {
		if resp.Error == nil {
			return resp, &Error{Code: CodeFailed, Message: "no error detail"}
		}
		return resp, resp.Error
	}
	return resp, nil
}

// DecodeResult decodes a successful response's result into v.
func DecodeResult(resp Response, v any) error {
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("syncapi: result: %w", err)
	}
	return nil
}

// ErrorCodeOf returns the code of an API error ("" for other errors).
func ErrorCodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
