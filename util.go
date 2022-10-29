package main



import (

	"fmt"
	"reflect"
	"bytes"
	"encoding/binary"

	"hpcstezos/ep11"
	pb "hpcstezos/grpc"

	"google.golang.org/grpc/status"

)
// Convert is a helper function for generating proper Grep11Error structures
func Convert(err error) (bool, *pb.Grep11Error) {
	if err == nil {
		return true, nil
	}

	fmt.Println((err))
	st, ok := status.FromError(err)

	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Server returned error: [%s]", err),
			Retry:  true,
		}
	}

	detail := st.Details()

	if len(detail) != 1 {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Error: [%s]", err),
			Retry:  true,
		}
	}

	err2, ok := detail[0].(*pb.Grep11Error)

	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Error [%s]: [%s]", reflect.TypeOf(detail[0]), err),
			Retry:  true,
		}
	}

	return false, err2
}

func AttributeMap(attrs ep11.EP11Attributes) map[ep11.Attribute]*pb.AttributeValue {
	rc := make(map[ep11.Attribute]*pb.AttributeValue)
	for attr, val := range attrs {
		rc[attr] = AttributeValue(val)
	}

	return rc
}

func AttributeValue(v interface{}) *pb.AttributeValue {
	if v == nil {
		return &pb.AttributeValue{}
	}

	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Bool:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeTF{AttributeTF: val.Bool()}}
	case reflect.String:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: []byte(val.String())}}
	case reflect.Slice:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: val.Bytes()}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeI{AttributeI: val.Int()}}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeI{AttributeI: int64(val.Uint())}}
	default:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, val)
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: buf.Bytes()}}
	}
}

func SetMechParm(parm []byte) *pb.Mechanism_ParameterB {
        return &pb.Mechanism_ParameterB{ParameterB: parm}
}

