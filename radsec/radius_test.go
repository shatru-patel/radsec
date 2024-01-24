package radsec

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func getAuthPacket() *radius.Packet {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, "test01")
	rfc2865.UserPassword_SetString(packet, "111111")
	rfc2865.CallingStationID_SetString(packet, "10.10.10.10")
	rfc2865.NASIdentifier_Set(packet, []byte("tradtest"))
	rfc2865.NASIPAddress_Set(packet, net.ParseIP("localhost"))
	rfc2865.NASPort_Set(packet, 0)
	rfc2865.NASPortType_Set(packet, 0)
	rfc2869.NASPortID_Set(packet, []byte("slot=2;subslot=2;port=22;vlanid=100;"))
	rfc2865.CalledStationID_SetString(packet, "11:11:11:11:11:11")
	rfc2865.CallingStationID_SetString(packet, "11:11:11:11:11:11")
	return packet
}

func TestTlsClient(t *testing.T) {
	//cert, err := tls.LoadX509KeyPair("/home/shatru/radsec/assets/radsec.tls.crt", "/home/shatru/radsec/assets/radsec.tls.key")
	cert, err := tls.LoadX509KeyPair("/home/shatru/radsec/assets/client.crt", "/home/shatru/radsec/assets/client.key")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", "localhost:2083", &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	})

	if err != nil {
		t.Fatal(err)
	}
	t.Log(conn)
	pkt := getAuthPacket()
	bs, err := pkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	myString := string(bs[:])
	fmt.Println("mystring ", myString)
	res, err := conn.Write(bs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("resr is ", res)
	time.Sleep(time.Second * 3)
}
