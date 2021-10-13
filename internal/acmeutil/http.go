package acmeutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type StatusError struct {
	Code int
	Body struct {
		Type        string `json:"type"`
		Detail      string `json:"detail"`
		Instance    string `json:"instance"`
		Subproblems []struct {
		} `json:"subproblems"`
	}
}

func (se StatusError) Error() string {
	return fmt.Sprintf("[%d] %q", se.Code, se.Body.Detail)
}

func (se StatusError) ShortType() string {
	if se.Body.Type == "" {
		return ""
	}
	errParts := strings.Split(se.Body.Type, ":acme:error:")
	if len(errParts) != 2 {
		return ""
	}
	return strings.ToLower(errParts[1])
}

func ErrorFromResponse(resp *http.Response) *StatusError {
	if resp.StatusCode < 400 {
		return nil
	}
	statusErr := &StatusError{Code: resp.StatusCode}
	err := json.NewDecoder(resp.Body).Decode(&statusErr.Body)
	if err != nil {
		statusErr.Body.Detail = fmt.Sprintf("<error decoding body: %v>", err)
	}
	return statusErr
}
