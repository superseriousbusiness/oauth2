package models_test

import (
	"testing"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

func TestValidatePlain(t *testing.T) {
	cc := models.CodeChallengePlain
	if !cc.Validate("plaintest", "plaintest") {
		t.Fatal("not valid")
	}
}

func TestValidateS256(t *testing.T) {
	cc := models.CodeChallengeS256
	if !cc.Validate("W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o=", "s256test") {
		t.Fatal("not valid")
	}
}

func TestValidateS256NoPadding(t *testing.T) {
	cc := models.CodeChallengeS256
	if !cc.Validate("W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o", "s256test") {
		t.Fatal("not valid")
	}
}
