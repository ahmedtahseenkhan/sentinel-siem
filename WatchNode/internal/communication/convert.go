package communication

import (
	"fmt"

	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/pkg/proto"
)

// DataPointToProto converts a models.DataPoint to proto.DataPoint.
func DataPointToProto(p models.DataPoint) *proto.DataPoint {
	dp := &proto.DataPoint{
		Type:      p.Type,
		Timestamp: p.Timestamp.UnixNano(),
		Fields:    make(map[string]*proto.Value),
		Tags:      p.Tags,
	}
	for k, v := range p.Fields {
		dp.Fields[k] = interfaceToValue(v)
	}
	return dp
}

func interfaceToValue(v interface{}) *proto.Value {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		return &proto.Value{Value: &proto.Value_StringValue{StringValue: x}}
	case int:
		return &proto.Value{Value: &proto.Value_IntValue{IntValue: int64(x)}}
	case int32:
		return &proto.Value{Value: &proto.Value_IntValue{IntValue: int64(x)}}
	case int64:
		return &proto.Value{Value: &proto.Value_IntValue{IntValue: x}}
	case uint64:
		return &proto.Value{Value: &proto.Value_IntValue{IntValue: int64(x)}}
	case float32:
		return &proto.Value{Value: &proto.Value_DoubleValue{DoubleValue: float64(x)}}
	case float64:
		return &proto.Value{Value: &proto.Value_DoubleValue{DoubleValue: x}}
	case bool:
		return &proto.Value{Value: &proto.Value_BoolValue{BoolValue: x}}
	case []byte:
		return &proto.Value{Value: &proto.Value_BytesValue{BytesValue: x}}
	default:
		return &proto.Value{Value: &proto.Value_StringValue{StringValue: fmt.Sprintf("%v", x)}}
	}
}
