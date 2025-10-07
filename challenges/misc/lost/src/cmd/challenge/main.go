package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"unitedctf2025/lost/internal/protoaddr"
	"unitedctf2025/lost/utils"

	"golang.org/x/crypto/ssh"
)

func main() {
	slog := slog.Default()

	addr := utils.GetEnvOrDefault("SSH_ADDR", "tcp4://0.0.0.0:10456")
	user := utils.GetEnvOrDefault("SSH_USER", "paul")
	pass := utils.GetEnvOrDefault("SSH_PASS", "i_hope_you_wont_need_this")
	flag := utils.GetEnvOrDefault("SSH_FLAG", "flag-placeholder")

	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-🌎🛰️",
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			slog.Info("Authentification", "remoteAddr", conn.RemoteAddr(), "method", method)
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() != user || string(password) != pass {
				slog.Warn("Invalid authentication", "remoteAddr", conn.RemoteAddr(), "user", conn.User(), "pass", string(password))
				return nil, fmt.Errorf("invalid authentication")
			}
			slog.Info("Valid authentication", "remoteAddr", conn.RemoteAddr(), "user", conn.User())
			return nil, nil
		},
	}

	serverConfig.AddHostKey(
		utils.StubPanic(
			ssh.NewSignerFromKey(
				utils.StubPanic(
					rsa.GenerateKey(rand.Reader, 2048)))))

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	listenAddr := utils.StubPanic(protoaddr.ParseAddr(addr))
	serverListener := utils.StubPanic(net.Listen(listenAddr.Protocol, listenAddr.Address()))
	slog.Info("Listening for SSH connections", "addr", listenAddr.String())

	clients := make(map[string]*ssh.ServerConn)
	flagReqs := make(map[string]string)
	syncLock := sync.Mutex{}
	wg := sync.WaitGroup{}

	go func() {
		for {
			serverConnection, err := serverListener.Accept()
			if err != nil {
				slog.Error("Failed to accept SSH connection", "error", err)
				return
			}
			remoteAddr := serverConnection.RemoteAddr().String()
			slog := slog.With("remoteAddr", remoteAddr)

			go func() {
				sshServer, channels, requests, err := ssh.NewServerConn(serverConnection, serverConfig)
				if err != nil {
					serverConnection.Close()
					if _, ok := err.(ssh.ServerAuthError); ok {
						slog.Info("Invalid authentification", "error", err)
						return
					}
					slog.Info("Invalid SSH connection", "error", err)
					return
				}
				wg.Add(1)

				utils.WithLock(func() {
					slog.Info("Created new SSH connection")
					clients[remoteAddr] = sshServer
				}, &syncLock)

				go func() {
					defer wg.Done()
					defer utils.WithLock(func() {
						slog.Info("Disposing SSH connection")
						delete(clients, remoteAddr)
						delete(flagReqs, remoteAddr)

						serverConnection.Close()
					}, &syncLock)

					utils.WaitAll(
						// Deny all channels
						func() {
							for newChannel := range channels {
								slog.Info("Rejecting channel", "type", newChannel.ChannelType())
								newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type '%s'", newChannel.ChannelType()))
							}
						},
						// Handle requests
						func() {
							for request := range requests {
								slog.Info("Received request", "type", request.Type)
								if uuid, ok := flagReqs[remoteAddr]; ok {
									if request.Type == uuid {
										slog.Info("Requested flag", "uuid", uuid)
										request.Reply(true, []byte(flag))
										sshServer.Close()
									} else {
										slog.Info("Requested flag but wrong uuid", "uuid", uuid, "requestedUuid", request.Type)
										request.Reply(false, nil)
									}
								} else {
									slog.Info("Requested flag but did not pass marco polo challenge")
									request.Reply(false, nil)
								}
							}
						},
					)
				}()

				go func() {
					defer serverConnection.Close()

					chanReceiver := make(chan ssh.Channel)
					go func() {
						for i := range 3 {
							channel, reqs, err := sshServer.OpenChannel("whereareyou", nil)
							if err != nil {
								if openErr, ok := err.(*ssh.OpenChannelError); ok {
									// Give the client a chance to open the channel
									if openErr.Reason == ssh.UnknownChannelType {
										slog.Error("Unknown channel type error returned by client, retrying", "attempt", i+1)
										time.Sleep(1 * time.Second)
										continue
									}
								}

								slog.Error("Failed to open 'whereareyou' channel", "error", err)
								chanReceiver <- nil
								close(chanReceiver)
								return
							}
							go ssh.DiscardRequests(reqs)

							slog.Info("Opened 'whereareyou' channel")
							chanReceiver <- channel
							close(chanReceiver)
							return
						}

						slog.Error("Remote client did not open 'whereareyou' channel")
						chanReceiver <- nil
						close(chanReceiver)
					}()

					select {
					case channel := <-chanReceiver:
						if channel == nil {
							break
						}
						defer channel.Close()

						_, err := channel.Write([]byte("marco"))
						if err != nil {
							slog.Error("Failed to write question to channel", "error", err)
							return
						}

						answer, err := utils.ReadN(channel, 512)
						if err != nil {
							slog.Error("Failed to read answer", "error", err)
							return
						}

						if string(utils.TrimNull(answer)) != "polo" {
							slog.Error("Invalid answer", "answer", string(utils.TrimNull(answer)))
							return
						}

						uuid := utils.Uuidv4()
						utils.WithLock(func() {
							flagReqs[remoteAddr] = uuid
						}, &syncLock)

						fmt.Fprintf(channel, "Identity validated! You can now create a request of type '%s' on the main channel to know where you are.", uuid)
						slog.Info("Passed 'marco polo' challenge", "uuid", uuid)

						time.Sleep(5 * time.Second)
						channel.Close()

					case <-time.After(10 * time.Second):
						slog.Error("Timeout waiting for channel")
					}
				}()
			}()
		}
	}()

	<-ctx.Done()
	utils.WaitAll(
		func() {
			utils.WithLock(func() {
				for _, client := range clients {
					client.Close()
				}
				serverListener.Close()
			}, &syncLock)
		},
		func() {
			wg.Wait()
		},
	)
}
