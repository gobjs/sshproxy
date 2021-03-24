package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/creack/pty"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func main() {
	l, err := net.Listen("tcp", ":10022")
	if err != nil {
		logger.Fatal("listen failed", zap.Error(err))
	}
	defer l.Close()

	logger.Info("server startup", zap.String("listen_addr", l.Addr().String()))

	for {
		cc, err := l.Accept()
		if err != nil {
			logger.Warn("accept failed", zap.Error(err))
		}

		go serve(context.Background(), cc)
	}
}

func serve(ctx context.Context, cc net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("server panic", zap.Any("panic", r))
		}
	}()
	defer cc.Close()
	sc, err := sshServerConn(cc)
	if err != nil {
		logger.Error("ssh connecting failed", zap.Error(err))
		return
	}
	defer sc.Close()
	sc.Serve(ctx)
}

func sessionAuthenticate(key, secret string) error {
	return nil
}

func sessionInfoRequest() (*sessInfo, error) {
	return sessInfoFromEnv(), nil
	//return nil, errors.New("not implemented")
}

func sessInfoFromEnv() *sessInfo {
	user, ok := os.LookupEnv("SSHPROXY_USER")
	if !ok {
		user = "root"
	}
	host, ok := os.LookupEnv("SSHPROXY_HOST")
	if !ok {
		user = "localhost"
	}
	portStr, ok := os.LookupEnv("SSHPROXY_PORT")
	if !ok {
		portStr = "22"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 22
	}
	password, ok := os.LookupEnv("SSHPROXY_PASSWORD")
	if !ok {
		user = "111111"
	}

	return &sessInfo{
		User:     user,
		Host:     host,
		Port:     port,
		Password: password,
	}
}

func sshServerConn(cc net.Conn) (*ServerConn, error) {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-bjs-sshproxy",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			err := sessionAuthenticate(conn.User(), string(password))
			if err != nil {
				logger.Info("authenticate failed",
					zap.Error(err),
					zap.String("user", conn.User()),
					zap.Any("client_ip", conn.RemoteAddr()))
				return nil, err
			}
			return nil, nil
		},
	}

	priHostKey, err := readHostKey()
	if err != nil {
		return nil, fmt.Errorf("read host key failed: %v", err)
	}
	cfg.AddHostKey(priHostKey)

	sc, chans, reqs, err := ssh.NewServerConn(cc, cfg)
	if err != nil {
		return nil, fmt.Errorf("new ssh server conn failed: %v", err)
	}

	logger.Info("new ssh connection from",
		zap.String("remote_addr", sc.RemoteAddr().String()),
		zap.ByteString("client_version", sc.ClientVersion()))
	return NewServerConn(sc, chans, reqs), nil
}

func readHostKey() (ssh.Signer, error) {
	priHostKey, err := ssh.ParsePrivateKey(serverKeyPem)
	if err != nil {
		return nil, fmt.Errorf("parse hostkey failed: %v", err)
	}
	return priHostKey, nil
}

type ServerConn struct {
	conn  *ssh.ServerConn
	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request
}

func (c *ServerConn) Serve(ctx context.Context) {
	go ssh.DiscardRequests(c.reqs)
	c.handleChannels(ctx)
}

func (c *ServerConn) handleChannels(ctx context.Context) {
	for ch := range c.chans {
		go c.handleChannel(ctx, ch)
	}
}

func (c *ServerConn) handleChannel(ctx context.Context, ch ssh.NewChannel) {
	logger.Debug("new chan", zap.String("chan_type", ch.ChannelType()), zap.Any("chan_extra_data", ch.ExtraData()))

	switch t := ch.ChannelType(); t {
	case "session":
		sess, err := handleSessionChannel(ch)
		if err != nil {
			c.Close()
			logger.Warn("handle session failed", zap.Error(err))
			return
		}
		sess.sessInfo, err = sessionInfoRequest()
		if err != nil {
			c.Close()
			logger.Warn("handle session failed", zap.Error(err))
			return
		}
		sess.serve(ctx)
	default:
		ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknnown channel type %q", t))
	}
}

type Session struct {
	mux  sync.Mutex
	ch   ssh.Channel
	reqs <-chan *ssh.Request
	envs []string

	ptyRequestMsg ptyRequestMsg
	ptmx          *os.File
	tty           *os.File
	started       bool

	sessInfo     *sessInfo
	proxySession *ssh.Session
}

type sessInfo struct {
	Host          string
	Port          int
	User          string
	Password      string
	PrivateKeyPem string
}

func (s *Session) serve(ctx context.Context) {
	defer s.ch.Close()

	for req := range s.reqs {
		logger.Debug("new req", zap.String("req_type", req.Type), zap.Any("req_payload", req.Payload))
		switch req.Type {
		case "pty-req":
			s.handlePtyReq(ctx, req)
		case "shell":
			go s.handleShellReq(ctx, req)
		case "env":
			s.handleEnvReq(ctx, req)
		case "window-change":
			s.handleWindowChangeReq(ctx, req)
		default:
			req.Reply(false, []byte(fmt.Sprintf("unknown req %q", req.Type)))
		}
	}
}

func (s *Session) handleShellReq(ctx context.Context, req *ssh.Request) {
	defer s.ch.Close()

	s.started = true

	if s.ptmx == nil || s.tty == nil {
		logger.Warn("ptmx is not initialized")
		req.Reply(false, nil)
		return
	}

	req.Reply(true, nil)

	if s.sessInfo == nil {
		logger.Warn("sessInfo not request")
		return
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(s.sessInfo.Host, strconv.Itoa(s.sessInfo.Port)), &ssh.ClientConfig{
		User: s.sessInfo.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.sessInfo.Password),
			ssh.PublicKeysCallback(func() (signers []ssh.Signer, err error) {
				signer, err := ssh.ParsePrivateKey([]byte(s.sessInfo.PrivateKeyPem))
				if err != nil {
					return nil, err
				}
				return []ssh.Signer{signer}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		logger.Warn("ssh dial failed", zap.Error(err))
		return
	}

	session, err := client.NewSession()
	if err != nil {
		logger.Warn("open session failed", zap.Error(err))
		return
	}
	s.proxySession = session

	modes := make(ssh.TerminalModes)
	modesBytes := []byte(s.ptyRequestMsg.Modelist)
	for {
		opcode := modesBytes[0]
		if opcode == 0 {
			break
		}

		argument := binary.BigEndian.Uint32(modesBytes[1:5])
		logger.Debug("modes", zap.Uint8("opcode", opcode), zap.Uint32("value", argument))

		modes[opcode] = argument
		modesBytes = modesBytes[5:]
	}
	err = session.RequestPty(s.ptyRequestMsg.Term, int(s.ptyRequestMsg.Rows), int(s.ptyRequestMsg.Columns), modes)
	if err != nil {
		logger.Warn("request pty failed", zap.Error(err))
		return
	}

	var once sync.Once
	closeOnce := func() {
		once.Do(func() {
			s.ch.Close()
			client.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer closeOnce()
		defer wg.Done()
		p, err := session.StdoutPipe()
		if err != nil {
			logger.Warn("StdoutPipe failed", zap.Error(err))
			return
		}
		io.Copy(s.ch, p)
	}()

	go func() {
		defer closeOnce()
		defer wg.Done()
		p, err := session.StdinPipe()
		if err != nil {
			logger.Warn("StdinPipe failed", zap.Error(err))
			return
		}
		io.Copy(p, s.ch)
	}()

	go func() {
		defer closeOnce()
		defer wg.Done()
		p, err := session.StderrPipe()
		if err != nil {
			logger.Warn("StderrPipe failed", zap.Error(err))
			return
		}
		io.Copy(s.ch, p)
	}()

	err = session.Shell()
	if err != nil {
		logger.Warn("request pty failed", zap.Error(err))
		return
	}

	wg.Wait()
	logger.Debug("session closed")
	s.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{Code: 0}))
}

type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

func (s *Session) handlePtyReq(ctx context.Context, req *ssh.Request) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.started {
		logger.Warn("session already started")
		return
	}

	err := ssh.Unmarshal(req.Payload, &s.ptyRequestMsg)
	if err != nil {
		logger.Warn("unmarshal pty request failed", zap.Error(err))
		return
	}

	s.ptmx, s.tty, err = pty.Open()
	if err != nil {
		req.Reply(false, nil)
		logger.Warn("open pty failed", zap.Error(err))
		return
	}

	req.Reply(true, nil)
}

func (s *Session) handleEnvReq(ctx context.Context, req *ssh.Request) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.started {
		logger.Warn("session already started")
		return
	}

	var payload struct {
		Key, Value string
	}
	err := ssh.Unmarshal(req.Payload, &payload)
	if err != nil {
		req.Reply(false, nil)
		logger.Warn("parse req payload failed", zap.Error(err))
		return
	}
	s.envs = append(s.envs, fmt.Sprintf("%s=%s", payload.Key, payload.Value))
	req.Reply(true, nil)
}

type ptyWindowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func (s *Session) handleWindowChangeReq(ctx context.Context, req *ssh.Request) {
	s.mux.Lock()
	defer s.mux.Unlock()

	var msg ptyWindowChangeMsg
	ssh.Unmarshal(req.Payload, &msg)
	logger.Debug("window changed", zap.Uint32("rows", msg.Rows), zap.Uint32("cols", msg.Columns))
	if s.proxySession != nil {
		s.proxySession.SendRequest("window-change", false, req.Payload)
	}
}

func handleSessionChannel(nch ssh.NewChannel) (*Session, error) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return nil, fmt.Errorf("session accept failed: %v", err)
	}

	return &Session{
		ch:   ch,
		reqs: reqs,
	}, nil
}

func (c *ServerConn) Close() error {
	return c.conn.Close()
}

func NewServerConn(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) *ServerConn {
	return &ServerConn{
		conn:  conn,
		chans: chans,
		reqs:  reqs,
	}
}
