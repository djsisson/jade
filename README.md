# Jade Authentication Project

A Go-based authentication project utilizing the Jade library to provide a seamless authentication experience.

## Overview

This project aims to demonstrate the usage of the Jade library for authentication purposes. It includes examples for various authentication providers, such as Google, GitHub, and custom providers.

## Features

- Authentication with multiple providers (Google, GitHub, etc.)
- Custom provider implementation
- Session management using JadeStore
- Middleware for checking user login status

## Installation

To install the project, run the following command:

```bash
go get github.com/djsisson/jade
```

## Usage

To use the project, import the `jade` package and use the provided functions for authentication and session management.

```go
import "github.com/djsisson/jade"
```

## Examples

The project includes several examples to demonstrate the usage of the Jade library:

- [examples/basic](cci:7://https://github.com/djsisson/jade/examples/basic:0:0-0:0): A basic example using Google authentication
- [examples/custom_provider](cci:7://https://github.com/djsisson/jade/examples/custom_provider:0:0-0:0): An example using a custom authentication provider
- [examples/custom_store](cci:7://https://github.com/djsisson/jade/examples/custom_store:0:0-0:0): An example using a custom session store

## Getting Started

To run the examples, navigate to the respective directory and execute the `main.go` file using the `go run` command.

## License

This project is licensed under the MIT License. See `LICENSE` for more information.
