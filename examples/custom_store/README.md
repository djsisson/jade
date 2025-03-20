## Custom Store Example

This example uses a custom session store.
This means only the session id is stored in the cookie, the rest would be in your own database
Allowing you to link a user to a session.

This example is using sqlite

Create a Google Dev Console project and obtain a client ID and client secret.

Set the `ClientID` and `ClientSecret` constants in the `main.go` file with your client ID and client secret.

To run the example, navigate to the `examples/custom_store` directory and execute the `main.go` file using the `go run` command.

```bash
go get github.com/djsisson/jade
cd examples/custom_store
go run main.go
```
