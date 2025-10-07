package main

import (
	"log/slog"
	"strings"
	"time"

	"unitedctf2025/lost/internal/protoaddr"
	"unitedctf2025/lost/utils"

	"golang.org/x/crypto/ssh"
)

func main() {
	slog := slog.Default()

	user := utils.GetEnvOrDefault("SSH_USER", "paul")
	pass := utils.GetEnvOrDefault("SSH_PASS", "i_hope_you_wont_need_this")
	addr := utils.GetEnvOrDefault("SSH_ADDR", "tcp4://127.0.0.1:10456")

	dialAddr := utils.StubPanic(protoaddr.ParseAddr(addr))
	conn, err := ssh.Dial(dialAddr.Protocol, dialAddr.Address(), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		slog.Error("Failed to dial", "error", err)
		return
	}
	slog = slog.With("addr", dialAddr.String())
	slog.Info("Connected to server")

	select {
	case newChannel := <-conn.HandleChannelOpen("whereareyou"):
		if newChannel == nil {
			slog.Error("Failed to open 'whereareyou' channel")
			break
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			slog.Error("Failed to accept 'whereareyou' channel", "error", err)
			break
		}
		slog.Info("Accepted 'whereareyou' channel")
		go ssh.DiscardRequests(requests)

		question := string(utils.TrimNull(utils.StubPanic(utils.ReadN(channel, 512))))
		slog.Info("Received question", "question", question)
		if question != "marco" {
			slog.Error("Invalid question", "question", question)
			break
		}

		slog.Info("Sending answer", "answer", "polo")
		_, err = channel.Write([]byte("polo"))
		if err != nil {
			slog.Error("Failed to write answer", "error", err)
			break
		}

		answer := string(utils.TrimNull(utils.StubPanic(utils.ReadN(channel, 512))))
		slog.Info("Received answer", "answer", answer)

		if len(answer) < 38 || !strings.Contains(answer, "'") {
			slog.Error("Invalid answer", "answer", answer)
			break
		}

		uuid := answer[strings.Index(answer, "'")+1 : strings.Index(answer, "'")+1+36]
		slog.Info("Extracted UUID", "uuid", uuid)

		slog.Info("Sending request", "uuid", uuid)
		ok, payload, err := conn.SendRequest(uuid, true, nil)
		if err != nil {
			slog.Error("Failed to send request", "error", err)
			break
		}
		if !ok {
			slog.Error("Request failed", "uuid", uuid)
			break
		}
		slog.Info("Received flag", "flag", string(payload))
	case <-time.After(10 * time.Second):
		slog.Error("Timed out")
		break
	}

	slog.Info("Closing connection")
	conn.Close()
}
