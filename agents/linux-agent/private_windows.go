package main

import "os"

func openPrivateDescriptor(filename string) (*os.File, error) { return os.Open(filename) }
