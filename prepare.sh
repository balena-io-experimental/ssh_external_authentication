#!/bin/sh

mkdir tmp

ssh-keygen -b 2048 -t rsa -f tmp/testServerKey -q -N ""
ssh-keygen -b 2048 -t rsa -f tmp/testClientKey -q -N ""

go run main.go -cmd sshck tmp/testServerKey tmp/testServerKey.pub.go