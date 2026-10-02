package appstore

import (
	"errors"
	"fmt"
	"testing"
)

func TestSignatureRequiredErrorClassifiesAppleRefusals(t *testing.T) {
	refusals := []int{404, 403, 401}

	for _, status := range refusals {
		err := fmt.Errorf("login: %w", &ResponseDecodeError{
			StatusCode:  status,
			ContentType: "text/html",
			Body:        "<html><head><title>404 Not Found</title></head></html>",
		})

		classified := signatureRequiredError(err)
		if classified == nil {
			t.Fatalf("status %d: expected a classification", status)
		}

		if !errors.Is(classified, ErrSignatureRequired) {
			t.Fatalf("status %d: %v does not wrap ErrSignatureRequired", status, classified)
		}
	}
}

func TestSignatureRequiredErrorIgnoresOtherFailures(t *testing.T) {
	cases := map[string]error{
		"not a decode error": errors.New("connection reset"),
		"server error": fmt.Errorf("login: %w", &ResponseDecodeError{
			StatusCode: 500, ContentType: "text/xml",
		}),
		"plist parse on a 200": fmt.Errorf("login: %w", &ResponseDecodeError{
			StatusCode: 200, ContentType: "text/xml",
		}),
	}

	for name, err := range cases {
		if got := signatureRequiredError(err); got != nil {
			t.Errorf("%s: expected no classification, got %v", name, got)
		}
	}
}
