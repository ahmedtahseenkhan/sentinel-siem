package decoder

import (
	"testing"

	"go.uber.org/zap"
)

// Proves the pfSense filterlog decoder extracts the fields the network rules
// need (src_ip/dst_ip/ports/action). This is the seam between "pfSense ships
// syslog" and "the recon/scan/DoS rules fire" — exactly the kind of integration
// boundary that shipped untested before.
func TestPfSenseFilterlogDecoder(t *testing.T) {
	e := NewSyslogEngine(zap.NewNop())
	if err := e.LoadFromDir("../../../decoders/syslog"); err != nil {
		t.Fatalf("load syslog decoders: %v", err)
	}

	cases := []struct {
		name string
		line string
		want map[string]string
	}{
		{
			name: "ipv4 tcp block",
			// rule,sub,anchor,tracker,iface,reason,action,dir,4,tos,ecn,ttl,id,offset,flags,protoid,proto,len,src,dst,sport,dport,...
			line: "90,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,52,203.0.113.5,192.168.1.10,44321,443,0,S,...",
			want: map[string]string{
				"action": "block", "direction": "in", "interface": "igb0",
				"protocol": "tcp", "src_ip": "203.0.113.5", "dst_ip": "192.168.1.10",
				"src_port": "44321", "dst_port": "443", "source": "pfsense",
			},
		},
		{
			name: "ipv4 udp pass",
			line: "12,,,1000000044,em1,match,pass,out,4,0x0,,64,0,0,none,17,udp,60,10.0.0.5,8.8.8.8,53124,53,40",
			want: map[string]string{
				"action": "pass", "direction": "out", "protocol": "udp",
				"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "src_port": "53124", "dst_port": "53",
			},
		},
		{
			name: "ipv4 icmp block (no ports)",
			line: "5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,192.168.1.5,8.8.8.8,request,1,2",
			want: map[string]string{
				"action": "block", "direction": "in", "protocol": "icmp",
				"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.Test("filterlog", tc.line)
			if !r.Matched {
				t.Fatalf("line not matched by any decoder: %q", tc.line)
			}
			for k, want := range tc.want {
				if got := r.Fields[k]; got != want {
					t.Errorf("field %q = %q, want %q (decoder=%s)", k, got, want, r.DecoderName)
				}
			}
			// ICMP must NOT get spurious ports from the tcp/udp child.
			if tc.name == "ipv4 icmp block (no ports)" {
				if _, ok := r.Fields["src_port"]; ok {
					t.Errorf("icmp should not have src_port, got %q (decoder=%s)", r.Fields["src_port"], r.DecoderName)
				}
			}
		})
	}
}
