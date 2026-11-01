package main

import "errors"

func lockState(_ string) (func(), error) { return nil, errors.New("Linux runtime is required") }
