package radsec

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"layeh.com/radius"
)

type packetResponseWriter struct {
	// listener that received the packet
	conn net.Conn
	addr net.Addr
}

type RadsecHandler interface {
	ServeRADIUS(w radius.ResponseWriter, r *radius.Request)
}

func (r *packetResponseWriter) Write(packet *radius.Packet) error {
	encoded, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.Write(encoded); err != nil {
		return err
	}
	return nil
}

// RadsecPacketServer listens for RADIUS requests on a packet-based protocols (e.g.
// UDP).
type RadsecPacketServer struct {
	// The address on which the server listens. Defaults to :1812.
	Addr string

	// The network on which the server listens. Defaults to udp.
	Network string

	// The source from which the secret is obtained for parsing and validating
	// the request.
	SecretSource radius.SecretSource

	// Handler which is called to process the request.
	Handler RadsecHandler

	// Skip incoming packet authenticity validation.
	// This should only be set to true for debugging purposes.
	InsecureSkipVerify bool

	// ErrorLog specifies an optional logger for errors
	// around packet accepting, processing, and validation.
	// If nil, logging is done via the log package's standard logger.
	// ErrorLog *log.Logger

	shutdownRequested int32

	mu          sync.Mutex
	ctx         context.Context
	ctxDone     context.CancelFunc
	listeners   map[net.Conn]uint
	lastActive  chan struct{} // closed when the last active item finishes
	activeCount int32
}

func (s *RadsecPacketServer) initLocked() {
	if s.ctx == nil {
		s.ctx, s.ctxDone = context.WithCancel(context.Background())
		s.listeners = make(map[net.Conn]uint)
		s.lastActive = make(chan struct{})
	}
}

func (s *RadsecPacketServer) activeAdd() {
	atomic.AddInt32(&s.activeCount, 1)
}

func (s *RadsecPacketServer) activeDone() {
	if atomic.AddInt32(&s.activeCount, -1) == -1 {
		close(s.lastActive)
	}
}

func parseTcpPacket(r io.Reader, secret []byte) (*radius.Packet, error) {
	var header struct {
		Code       uint8
		Identifier uint8
		Length     uint16
	}

	err := binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return nil, err
	}

	s := unsafe.Sizeof(header)
	var data = make([]byte, header.Length-uint16(s))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	attrs, err := radius.ParseAttributes(data[16:])
	if err != nil {
		return nil, err
	}

	packet := &radius.Packet{
		Code:       radius.Code(header.Code),
		Identifier: header.Identifier,
		Secret:     secret,
		Attributes: attrs,
	}
	copy(packet.Authenticator[:], data[0:16])
	return packet, nil
}

// Serve accepts incoming connections on conn.
func (s *RadsecPacketServer) Serve(conn net.Conn) error {
	if s.Handler == nil {
		return errors.New("radius: nil RadsecHandler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}
	fmt.Println("Serv")
	s.mu.Lock()
	s.initLocked()
	if atomic.LoadInt32(&s.shutdownRequested) == 1 {
		s.mu.Unlock()
		return radius.ErrServerShutdown
	}

	s.listeners[conn]++
	s.mu.Unlock()

	type requestKey struct {
		IP         string
		Identifier byte
	}

	var (
		requestsLock sync.Mutex
		requests     = map[requestKey]struct{}{}
	)

	s.activeAdd()
	defer func() {
		s.mu.Lock()
		s.listeners[conn]--
		if s.listeners[conn] == 0 {
			delete(s.listeners, conn)
		}
		s.mu.Unlock()
		s.activeDone()
	}()

	secret, err := s.SecretSource.RADIUSSecret(s.ctx, conn.RemoteAddr())
	if err != nil {
		fmt.Errorf("radius: error fetching from secret source: %v", err)
		return err
	}
	fmt.Println("Serv1")

	if len(secret) == 0 {
		fmt.Errorf("radius: empty secret returned from secret source")
		return err
	}
	//fmt.Println("conn ", string(conn))
	r := bufio.NewReader(conn)
	fmt.Println("r is ")
	for {
		//fmt.Println("Serv2")

		pkt, err := parseTcpPacket(r, secret)
		fmt.Println("error is ", err)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("radius: connection closed by client %s\n", conn.RemoteAddr())
				return err
			}
			if _, ok := err.(net.Error); ok {
				fmt.Printf("radius: connection error %s: %v\n", conn.RemoteAddr(), err)
				return err
			}
			fmt.Errorf("radius: unable to parse packet: %v", err)
			continue
		}
		fmt.Println("Serv4")
		s.activeAdd()
		go func(packet *radius.Packet, conn net.Conn) {
			fmt.Println("Serv3")

			defer s.activeDone()

			key := requestKey{
				IP:         conn.RemoteAddr().String(),
				Identifier: packet.Identifier,
			}

			requestsLock.Lock()
			if _, ok := requests[key]; ok {
				requestsLock.Unlock()
				return
			}
			requests[key] = struct{}{}
			requestsLock.Unlock()

			response := packetResponseWriter{
				conn: conn,
				addr: conn.RemoteAddr(),
			}

			defer func() {
				requestsLock.Lock()
				delete(requests, key)
				requestsLock.Unlock()
			}()

			request := radius.Request{
				LocalAddr:  conn.LocalAddr(),
				RemoteAddr: conn.RemoteAddr(),
				Packet:     packet,
			}

			s.Handler.ServeRADIUS(&response, &request)
		}(pkt, conn)
		fmt.Println("Serv5")

	}
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *RadsecPacketServer) ListenAndServe(capath, crtfile, keyfile string) error {
	crt, err := tls.LoadX509KeyPair(crtfile, keyfile)
	if err != nil {
		return err
	}
	ca, err := ioutil.ReadFile(capath)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{crt},
		Time:         time.Now,
		Rand:         rand.Reader,
	}

	if s.Handler == nil {
		return errors.New("radius: nil RadsecHandler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	addrStr := fmt.Sprintf(":%d", 2083)
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "tcp"
	if s.Network != "" {
		network = s.Network
	}

	pc, err := tls.Listen(network, addrStr, tlsConfig)
	if err != nil {
		return err
	}
	defer pc.Close()
	fmt.Println("pc value is ", pc)
	for {
		conn, err := pc.Accept()
		fmt.Println("conn value-- is ", conn)

		if err != nil {
			continue
		}
		go s.Serve(conn)
	}
}

func (s *RadsecPacketServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if atomic.CompareAndSwapInt32(&s.shutdownRequested, 0, 1) {
		for listener := range s.listeners {
			listener.Close()
		}

		s.ctxDone()
		s.activeDone()
	}
	s.mu.Unlock()

	select {
	case <-s.lastActive:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
