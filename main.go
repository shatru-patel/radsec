package main

import (
	"fmt"

	e "example.com/m/v2/radsec"
	"golang.org/x/sync/errgroup"
)

var g errgroup.Group

func ListenRadsecServer(service *e.RadsecService) error {

	caCert := "/home/shatru/radsec/assets/radsec_ca.crt"
	serverCert := "/home/shatru/radsec/assets/radsec_server.crt"
	serverKey := "/home/shatru/radsec/assets/radsec_server.key"

	server := e.RadsecPacketServer{
		Addr:               fmt.Sprintf("%s:%d", "localhost", 2083),
		Handler:            service,
		SecretSource:       service,
		InsecureSkipVerify: true,
	}

	fmt.Printf("Starting Radius Resec server on %s\n", server.Addr)
	err := server.ListenAndServe(caCert, serverCert, serverKey)
	if err != nil {
		fmt.Printf("Radius Resec server error: %s\n", err)
	}
	return err
}

func NewRadiusService() *e.RadiusService {
	s := &e.RadiusService{
		AuthRateCache: make(map[string]e.AuthRateUser),
	}
	fmt.Println("s value is ", s)
	return s
}

func main() {
	fmt.Println("start the Radsec main")
	radiusService := NewRadiusService()
	g.Go(func() error {
		radsec := e.NewRadsecService(
			e.NewAuthService(radiusService),
			e.NewAcctService(radiusService),
		)
		return ListenRadsecServer(radsec)
	})
	select {}
}
