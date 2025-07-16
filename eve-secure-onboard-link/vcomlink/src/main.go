// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	address  = "127.0.0.1"
	port     = 9191
	waitTime = 1000 * time.Second
)

func isVsockSupported() bool {
	_, err := os.Stat("/sys/module/vsock")
	return err == nil
}

func isVsockLoopbackSupported() bool {
	_, err := os.Stat("/sys/module/vsock_loopback")
	return err == nil
}

func tcpListener() (net.Listener, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP socket: %v", err)
	}

	// Don't wait for TIME_WAIT sockets to be released.
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("setsockopt SO_REUSEADDR error: %v", err)
	}
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return nil, fmt.Errorf("setsockopt SO_REUSEPORT error: %v", err)
	}

	addr := unix.SockaddrInet4{
		Port: port,
	}
	if err := unix.Bind(sock, &addr); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to bind TCP socket: %v", err)
	}
	if err := unix.Listen(sock, unix.SOMAXCONN); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to listen on TCP socket: %v", err)
	}

	f, err := net.FileListener(os.NewFile(uintptr(sock), fmt.Sprintf("eve_vsock_%d_listener", addr.Port)))
	if err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to create file net listener: %v", err)
	}

	return f, nil
}

func tcpDial() (net.Conn, error) {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address: %s", address)
	}
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte(ip),
	}
	sockfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("Error creating socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("Error connecting to server: %v", err)
	}

	f, err := net.FileConn(os.NewFile(uintptr(sockfd), "tcp_dial"))
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("Error creating file connection: %v", err)
	}

	return f, nil
}

func vsockDial(cid, port uint32) (net.Conn, error) {
	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	sockfd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating VSOCK socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("error connecting to VSOCK server: %v", err)
	}

	return &VSOCKConn{fd: sockfd}, nil
}

func vsockClientTcpTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return tcpDial() // Use tcpDial as the connection handler
		},
	}
}

func vsockClientVsockTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return vsockDial(unix.VMADDR_CID_LOCAL, hostVPort) // Use vsockDial as the connection handler
		},
	}
}

func getClient() *http.Client {
	if isVsockSupported() && isVsockLoopbackSupported() {
		return &http.Client{
			Transport: vsockClientVsockTransport(),
			Timeout:   waitTime,
		}
	}
	return &http.Client{
		Transport: vsockClientTcpTransport(),
		Timeout:   waitTime,
	}
}

func main() {
	getOwnerCred = func() (string, error) {
		return "", nil
	}

	// set vsock addr to loopback
	cidAddr = unix.VMADDR_CID_LOCAL
	if isVsockSupported() && isVsockLoopbackSupported() {
		fmt.Println("VSOCK is supported, using VSOCK transport")
		startVcomServer(vsockNetListener)
	} else {
		fmt.Println("VSOCK is not supported, using TCP transport")
		startVcomServer(tcpListener)
	}
}
