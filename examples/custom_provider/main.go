package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/djsisson/jade"
	"github.com/djsisson/jade/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

const (
	port         = 1323
	ClientID     = "CLIENTID"
	ClientSecret = "CLIENTSECRET"
	CustomIssuer = "https://accounts.google.com"
)

var (
	CustomScopes      = []string{"openid", "profile", "email"}
	CustomCallbackURL = fmt.Sprintf("http://localhost:%d/auth/custom/callback", port)
)

type CustomClaims struct {
	ID            string `json:"sub,omitempty"`
	Issuer        string `json:"iss,omitempty"`
	Name          string `json:"name,omitempty"`
	FirstName     string `json:"given_name,omitempty"`
	LastName      string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Locale        string `json:"locale,omitempty"`
	HostedDomain  string `json:"hd,omitempty"`
}

func (u *CustomClaims) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            u.ID,
		Name:          u.Name,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Picture:       u.Picture,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Locale:        u.Locale,
	}
}

func main() {
	pr, err := jade.NewOIDCProvider[*CustomClaims](&jade.OIDCOptions{
		Options: jade.Options{
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
			Scopes:       CustomScopes,
			CallbackURL:  CustomCallbackURL,
		},
		Name:     "custom",
		Issuer:   CustomIssuer,
		UseNonce: true,
		UsePKCE:  true,
		AuthOptions: []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
			jade.WithForcedApprovalPrompt(),
		},
	})
	if err != nil {
		panic(err)
	}
	jade.UseProviders(pr)
	st := session.NewJadeStore(session.WithCookiePrefix("custom"))

	e := echo.New()
	e.Use(loggedIn(st))
	e.GET("/", func(c echo.Context) error {
		b := c.Get("loggedin").(bool)
		t, _ := template.New("index").Parse(indexTemplate)
		t.Execute(c.Response(), b)
		return nil
	})
	e.GET("/login", func(c echo.Context) error {
		t, _ := template.New("login").Parse(loginTemplate)
		t.Execute(c.Response(), nil)
		return nil
	}, authenticated(false, "/"))
	e.GET("/auth/:provider", func(c echo.Context) error {
		err := st.BeginAuth(c.Request(), c.Response(), c.Param("provider"), "/user")
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return echo.ErrBadRequest
		}
		return nil
	}, authenticated(false, "/"))
	e.GET("/auth/:provider/callback", func(c echo.Context) error {
		err := st.CompleteAuth(c.Request(), c.Response())
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return echo.ErrBadRequest
		}
		return nil
	}, authenticated(false, "/"))
	e.GET("/logout", func(c echo.Context) error {
		return st.DeleteSession(c.Request(), c.Response(), "/")
	}, authenticated(true, "/login"))
	e.GET("/user", func(c echo.Context) error {
		u := c.Get("user").(*jade.User)
		t, _ := template.New("user").Parse(userTemplate)
		t.Execute(c.Response(), u)
		return nil
	}, authenticated(true, "/login"))
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

// loggedIn is a middleware function that checks if a user is logged in.
// It retrieves user data from the session store using the provided JadeStore.
// If the user data is successfully retrieved, it sets the "user" and "loggedin"
// values in the context to the user data and true, respectively. If not, it sets
// "loggedin" to false. The middleware then calls the next handler in the chain.

func loggedIn(st session.JadeStore) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u, err := st.GetUserData(c.Request(), c.Response())
			c.Set("loggedin", false)
			if err == nil {
				c.Set("user", u)
				c.Set("loggedin", true)
			}
			return next(c)
		}
	}
}

// authenticated is a middleware function that checks if a user is authenticated
// according to the specified value v. If the value of "loggedin" in the context
// matches v, the middleware calls the next handler in the chain. If not, it
// redirects the request to the specified redirect URL.
func authenticated(v bool, redirect string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			b := c.Get("loggedin").(bool)
			if b != v {
				return c.Redirect(http.StatusSeeOther, redirect)
			}
			return next(c)
		}
	}
}

var indexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Index</title>
</head>
<body>
{{if .}}
	<a href="/user">User</a>
{{else}}
	<a href="/login">Login</a>
{{end}}
</body>
</html>`

var loginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Login</title>
</head>
<body>
	<a href="/auth/custom">Login With Custom Provider</a>
</body>
</html>`

var userTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>User</title>
</head>
<body>
	<div>{{.Name}}</div><br/>
	<img src="{{.Picture}}" referrerPolicy="no-referrer"><br/>
	<div>{{.Email}}</div><br/>
	<br/>
	<div><a href="/logout">Logout</a></div>
</body>
</html>`
