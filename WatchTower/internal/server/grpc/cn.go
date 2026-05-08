package grpc

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type ctxKeyClientCN struct{}

// PeerCN extracts the Common Name from the mTLS peer certificate attached to
// the gRPC context. Returns an empty string when TLS is not in use.
func PeerCN(ctx context.Context) string {
	cn, _ := ctx.Value(ctxKeyClientCN{}).(string)
	return cn
}

// extractCNFromContext reads the peer TLS leaf certificate and returns its CN.
func extractCNFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", nil
	}
	state := tlsInfo.State.(tls.ConnectionState)
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate presented")
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}

// contextWithCN enriches ctx with the peer's certificate CN.
func contextWithCN(ctx context.Context) context.Context {
	cn, _ := extractCNFromContext(ctx)
	return context.WithValue(ctx, ctxKeyClientCN{}, cn)
}
