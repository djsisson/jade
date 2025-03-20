package jade

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Token struct {
	*oauth2.Token
	*oidc.IDToken
}
