package grpc

import (
	"context"
	"time"

	"go.uber.org/zap"
	grpcLib "google.golang.org/grpc"
)

func UnaryLoggingInterceptor(logger *zap.Logger) grpcLib.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpcLib.UnaryServerInfo, handler grpcLib.UnaryHandler) (interface{}, error) {
		ctx = contextWithCN(ctx)
		start := time.Now()
		resp, err := handler(ctx, req)
		logger.Debug("grpc unary",
			zap.String("method", info.FullMethod),
			zap.String("peer_cn", PeerCN(ctx)),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
		return resp, err
	}
}

// StreamCNInterceptor injects the peer certificate CN into streaming call contexts.
func StreamCNInterceptor() grpcLib.StreamServerInterceptor {
	return func(srv interface{}, ss grpcLib.ServerStream, info *grpcLib.StreamServerInfo, handler grpcLib.StreamHandler) error {
		wrapped := &cnServerStream{ServerStream: ss, ctx: contextWithCN(ss.Context())}
		return handler(srv, wrapped)
	}
}

// cnServerStream wraps grpc.ServerStream to carry an enriched context.
type cnServerStream struct {
	grpcLib.ServerStream
	ctx context.Context
}

func (s *cnServerStream) Context() context.Context { return s.ctx }
