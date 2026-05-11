// Package syslog implements a UDP + TCP syslog receiver (RFC 3164 / RFC 5424).
// Firewalls, routers, and switches send messages here; the server parses them
// into models.Event and feeds them directly into the WatchTower rules engine.
package syslog

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

const defaultMaxSize = 64 * 1024 // 64 KB

// EventSink matches engine.Engine so we can call Ingest without a circular import.
type EventSink interface {
	Ingest(event *models.Event)
}

// Server listens for syslog messages on UDP and TCP.
type Server struct {
	addr    string
	maxSize int
	sink    EventSink
	logger  *zap.Logger
	stopCh  chan struct{}
}

func New(addr string, maxSize int, sink EventSink, logger *zap.Logger) *Server {
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}
	return &Server{
		addr:    addr,
		maxSize: maxSize,
		sink:    sink,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start launches UDP and TCP listeners in background goroutines.
func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("syslog resolve udp: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("syslog udp listen: %w", err)
	}
	go s.serveUDP(udpConn)

	tcpLis, err := net.Listen("tcp", s.addr)
	if err != nil {
		// TCP is optional — some senders only use UDP
		s.logger.Warn("syslog TCP listener failed (UDP only)", zap.Error(err))
	} else {
		go s.serveTCP(tcpLis)
	}

	s.logger.Info("syslog receiver started",
		zap.String("addr", s.addr),
		zap.String("protocols", "UDP+TCP"),
	)
	return nil
}

func (s *Server) Stop() {
	close(s.stopCh)
}

// serveUDP reads datagrams in a tight loop.
func (s *Server) serveUDP(conn *net.UDPConn) {
	defer conn.Close()
	buf := make([]byte, s.maxSize)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		msg := string(buf[:n])
		s.handle(msg, src.IP.String())
	}
}

// serveTCP accepts connections; each line is one syslog message.
func (s *Server) serveTCP(lis net.Listener) {
	defer lis.Close()
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		conn, err := lis.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	src := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		src = addr.IP.String()
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, s.maxSize), s.maxSize)
	for scanner.Scan() {
		s.handle(scanner.Text(), src)
	}
}

// handle parses one syslog message and ingests it.
func (s *Server) handle(raw, srcIP string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	event := parse(raw, srcIP)
	s.sink.Ingest(event)
}

// ── Parsers ───────────────────────────────────────────────────────────────────

// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
var rfc3164RE = regexp.MustCompile(`^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$`)

// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
var rfc5424RE = regexp.MustCompile(`^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)

func parse(raw, srcIP string) *models.Event {
	ts := time.Now().UnixMilli()
	fields := map[string]interface{}{
		"raw_message": raw,
		"src_ip":      srcIP,
	}

	var hostname, appName, message, facility, severity string
	eventType := "syslog"

	// Try RFC 5424 first (has version digit after PRI)
	if m := rfc5424RE.FindStringSubmatch(raw); len(m) == 10 {
		pri, _ := strconv.Atoi(m[1])
		fac, sev := priToFacilitySeverity(pri)
		facility = fac
		severity = sev
		hostname = nilDash(m[4])
		appName = nilDash(m[5])
		message = strings.TrimSpace(m[9])
		eventType = "syslog.rfc5424"
		fields["version"]    = m[2]
		fields["timestamp"]  = m[3]
		fields["procid"]     = nilDash(m[6])
		fields["msgid"]      = nilDash(m[7])
		fields["structured"] = nilDash(m[8])
	} else if m := rfc3164RE.FindStringSubmatch(raw); len(m) == 6 {
		pri, _ := strconv.Atoi(m[1])
		fac, sev := priToFacilitySeverity(pri)
		facility = fac
		severity = sev
		hostname = m[3]
		appName = strings.TrimSpace(m[4])
		message = strings.TrimSpace(m[5])
		eventType = "syslog.rfc3164"
		fields["timestamp"] = m[2]
	} else {
		// Unparseable — store raw
		message = raw
	}

	fields["hostname"] = hostname
	fields["app_name"] = appName
	fields["message"]  = message
	fields["facility"] = facility
	fields["severity"] = severity

	return &models.Event{
		ID:        uuid.New().String(),
		Timestamp: ts,
		Type:      eventType,
		AgentID:   "syslog:" + srcIP,
		AgentName: hostname,
		Fields:    fields,
		Tags: map[string]string{
			"source":   "syslog",
			"src_ip":   srcIP,
			"facility": facility,
			"severity": severity,
		},
	}
}

var facilities = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severities = []string{
	"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
}

func priToFacilitySeverity(pri int) (string, string) {
	fac := pri >> 3
	sev := pri & 0x7
	facStr := "unknown"
	if fac >= 0 && fac < len(facilities) {
		facStr = facilities[fac]
	}
	sevStr := "unknown"
	if sev >= 0 && sev < len(severities) {
		sevStr = severities[sev]
	}
	return facStr, sevStr
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
