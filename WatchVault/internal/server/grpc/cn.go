package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// allowedManagerCNs is the set of certificate Common Names that are permitted
// to ingest data into WatchVault. Add the CN used in your WatchTower cert here.
// Override at startup via config if needed.
var allowedManagerCNs = map[string]bool{
	"watchtower": true,
	"manager":    true,
}

type ctxKeyClientCN struct{}

// PeerCN extracts the CN from the mTLS peer certificate in the gRPC context.
func PeerCN(ctx context.Context) string {
	cn, _ := ctx.Value(ctxKeyClientCN{}).(string)
	return cn
}

func extractCNFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", nil
	}
	state := tlsInfo.State
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate presented")
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}

func contextWithCN(ctx context.Context) context.Context {
	cn, _ := extractCNFromContext(ctx)
	return context.WithValue(ctx, ctxKeyClientCN{}, cn)
}

// ValidateManagerCN returns an error if the peer CN is not in the allowed set.
// When TLS is not configured (cn == ""), validation is skipped.
func ValidateManagerCN(ctx context.Context) error {
	cn := PeerCN(ctx)
	if cn == "" {
		return nil
	}
	if !allowedManagerCNs[cn] {
		return fmt.Errorf("peer CN %q is not an authorised manager", cn)
	}
	return nil
}
