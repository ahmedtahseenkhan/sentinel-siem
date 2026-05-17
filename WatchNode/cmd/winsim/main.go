// winsim simulates a Windows endpoint agent for Sentinel SIEM testing.
// It registers with WatchTower and continuously sends synthetic Windows
// Security Event Log events, process events, and network connections so that
// detection rules, UEBA, and dashboards can be exercised without a real Windows host.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"os"
	"time"

	"github.com/watchnode/watchnode/pkg/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var (
	managerURL  = envOr("WINSIM_MANAGER_URL", "haproxy:50051")
	agentName   = envOr("WINSIM_AGENT_NAME", "windows-sim-1")
	enrollToken = envOr("WINSIM_ENROLL_TOKEN", "sentinel-enroll-secret-2024")
)

var (
	usernames = []string{"jsmith", "adavis", "mbrown", "lwhite", "rjones", "admin", "svc_backup"}
	sourceIPs = []string{"192.168.1.50", "192.168.1.51", "10.0.0.5", "10.0.0.12", "172.16.0.3", "185.220.101.1"}
	processes = []string{"cmd.exe", "powershell.exe", "explorer.exe", "svchost.exe", "lsass.exe", "chrome.exe", "notepad.exe", "certutil.exe", "regsvr32.exe", "mimikatz.exe"}
	destIPs   = []string{"8.8.8.8", "1.1.1.1", "142.250.80.46", "185.220.101.1", "10.10.10.5", "172.16.50.1", "192.168.200.1"}
	procHashes = []string{
		"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
		"2c624232cdd221771294dfbb310acbc8be44bba72b6a7b8b8001e3c7fb308d3",
		"19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7",
		"4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb5cd6ceaffa20e8956",
		"ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
	}
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	agentID := newUUID()
	logger.Info("winsim starting",
		zap.String("agent_id", agentID),
		zap.String("agent_name", agentName),
		zap.String("manager", managerURL),
	)

	ctx := context.Background()

	conn, err := grpc.DialContext(ctx, managerURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    60 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		logger.Fatal("failed to connect to manager", zap.Error(err))
	}
	defer conn.Close()

	client := proto.NewAgentServiceClient(conn)

	regResp, err := client.Register(ctx, &proto.RegistrationRequest{
		AgentId:  agentID,
		Hostname: agentName,
		Os:       "Windows",
		Platform: "windows",
		Version:  "10.0.19045",
		Labels: map[string]string{
			"environment":   "test",
			"team":          "security",
			"_enroll_token": enrollToken,
			"os_name":       "Windows 10 Enterprise",
		},
	})
	if err != nil {
		logger.Fatal("registration failed", zap.Error(err))
	}
	if !regResp.Accepted {
		logger.Fatal("registration rejected", zap.String("msg", regResp.Message))
	}
	if regResp.AgentId != "" {
		agentID = regResp.AgentId
	}
	logger.Info("registered with WatchTower", zap.String("agent_id", agentID))

	stream, err := client.StreamData(ctx)
	if err != nil {
		logger.Fatal("failed to open stream", zap.Error(err))
	}

	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}()

	go func() {
		hb := proto.NewAgentServiceClient(conn)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_, _ = hb.Heartbeat(ctx, &proto.HeartbeatRequest{
				AgentId:   agentID,
				Timestamp: time.Now().UnixMilli(),
				Status:    "active",
			})
		}
	}()

	loginTicker     := time.NewTicker(20 * time.Second)
	processTicker   := time.NewTicker(12 * time.Second)
	networkTicker   := time.NewTicker(8 * time.Second)
	bruteForceTimer := time.NewTicker(3 * time.Minute)
	defer loginTicker.Stop()
	defer processTicker.Stop()
	defer networkTicker.Stop()
	defer bruteForceTimer.Stop()

	// Send initial burst so the dashboard shows data immediately
	sendLoginBurst(stream, agentID, false, 3)
	sendNetworkBurst(stream, agentID, 5)
	sendProcessBurst(stream, agentID, 4)

	logger.Info("winsim running — sending synthetic Windows events", zap.String("agent_id", agentID))

	for {
		select {
		case <-loginTicker.C:
			if mrand.Intn(5) == 0 {
				sendFailedLogin(stream, agentID, pick(usernames), pick(sourceIPs))
			} else {
				sendSuccessLogin(stream, agentID, pick(usernames), pick(sourceIPs))
			}

		case <-processTicker.C:
			sendProcessCreate(stream, agentID, pick(processes), pick(procHashes))

		case <-networkTicker.C:
			sendNetworkConn(stream, agentID, pick(destIPs), mrand.Intn(65535)+1)

		case <-bruteForceTimer.C:
			// Brute-force simulation: N failures from same IP then success
			// → triggers brute_force_success UEBA anomaly
			attackIP := pick(sourceIPs)
			attackUser := pick(usernames)
			failCount := mrand.Intn(5) + 5
			logger.Info("winsim: simulating brute-force attack",
				zap.String("ip", attackIP),
				zap.String("user", attackUser),
				zap.Int("failures", failCount),
			)
			for i := 0; i < failCount; i++ {
				sendFailedLogin(stream, agentID, attackUser, attackIP)
				time.Sleep(300 * time.Millisecond)
			}
			time.Sleep(2 * time.Second)
			sendSuccessLogin(stream, agentID, attackUser, attackIP)
			// Occasionally spawn a suspicious process post-compromise
			if mrand.Intn(3) == 0 {
				time.Sleep(1 * time.Second)
				sendProcessCreate(stream, agentID, "mimikatz.exe",
					"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
			}
		}
	}
}

// ── Event senders ─────────────────────────────────────────────────────────────

func sendSuccessLogin(stream proto.AgentService_StreamDataClient, agentID, username, srcIP string) {
	send(stream, agentID, "log.eventlog", fmap{
		"win_event_id":        intVal(4624),
		"win_channel":         strVal("Security"),
		"win_TargetUserName":  strVal(username),
		"win_IpAddress":       strVal(srcIP),
		"win_LogonType":       intVal(3),
		"win_SubjectUserName": strVal("SYSTEM"),
		"win_WorkstationName": strVal(fmt.Sprintf("WS-%d", mrand.Intn(50)+1)),
		"message":             strVal(fmt.Sprintf("An account was successfully logged on. User: %s From: %s", username, srcIP)),
	})
}

func sendFailedLogin(stream proto.AgentService_StreamDataClient, agentID, username, srcIP string) {
	send(stream, agentID, "log.eventlog", fmap{
		"win_event_id":       intVal(4625),
		"win_channel":        strVal("Security"),
		"win_TargetUserName": strVal(username),
		"win_IpAddress":      strVal(srcIP),
		"win_LogonType":      intVal(3),
		"win_FailureReason":  strVal("%%2313"),
		"message":            strVal(fmt.Sprintf("An account failed to log on. User: %s From: %s", username, srcIP)),
	})
}

func sendProcessCreate(stream proto.AgentService_StreamDataClient, agentID, name, hash string) {
	send(stream, agentID, "process.new", fmap{
		"name":         strVal(name),
		"sha256":       strVal(hash),
		"pid":          intVal(int64(mrand.Intn(60000) + 1000)),
		"ppid":         intVal(int64(mrand.Intn(5000) + 1)),
		"user":         strVal(pick(usernames)),
		"win_event_id": intVal(4688),
		"win_channel":  strVal("Security"),
		"message":      strVal(fmt.Sprintf("A new process has been created. Process Name: %s", name)),
	})
}

func sendNetworkConn(stream proto.AgentService_StreamDataClient, agentID, rip string, rport int) {
	send(stream, agentID, "network.connection", fmap{
		"raddr":     strVal(rip),
		"rport":     intVal(int64(rport)),
		"laddr":     strVal("10.0.0.100"),
		"lport":     intVal(int64(mrand.Intn(60000) + 1024)),
		"status":    strVal("ESTABLISHED"),
		"protocol":  strVal("tcp"),
		"bytes_out": intVal(int64(mrand.Intn(1024*1024) + 1024)),
		"bytes_in":  intVal(int64(mrand.Intn(512*1024) + 512)),
	})
}

func sendLoginBurst(stream proto.AgentService_StreamDataClient, agentID string, failed bool, n int) {
	for i := 0; i < n; i++ {
		if failed {
			sendFailedLogin(stream, agentID, pick(usernames), pick(sourceIPs))
		} else {
			sendSuccessLogin(stream, agentID, pick(usernames), pick(sourceIPs))
		}
	}
}

func sendNetworkBurst(stream proto.AgentService_StreamDataClient, agentID string, n int) {
	for i := 0; i < n; i++ {
		sendNetworkConn(stream, agentID, pick(destIPs), mrand.Intn(65535)+1)
	}
}

func sendProcessBurst(stream proto.AgentService_StreamDataClient, agentID string, n int) {
	for i := 0; i < n; i++ {
		sendProcessCreate(stream, agentID, pick(processes), pick(procHashes))
	}
}

// ── gRPC helpers ──────────────────────────────────────────────────────────────

type fmap map[string]*proto.Value

func send(stream proto.AgentService_StreamDataClient, agentID, eventType string, f fmap) {
	protoFields := make(map[string]*proto.Value, len(f))
	for k, v := range f {
		protoFields[k] = v
	}
	_ = stream.Send(&proto.DataBatch{
		AgentId:   agentID,
		Timestamp: time.Now().UnixMilli(),
		Points: []*proto.DataPoint{
			{
				Type:      eventType,
				Timestamp: time.Now().UnixMilli(),
				Fields:    protoFields,
			},
		},
	})
}

func strVal(s string) *proto.Value {
	return &proto.Value{Value: &proto.Value_StringValue{StringValue: s}}
}

func intVal(i int64) *proto.Value {
	return &proto.Value{Value: &proto.Value_IntValue{IntValue: i}}
}

func pick(slice []string) string {
	return slice[mrand.Intn(len(slice))]
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:]),
	)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
