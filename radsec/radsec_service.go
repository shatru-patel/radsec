package radsec

import (
	"context"
	"fmt"
	"net"
	"time"

	"layeh.com/radius"
)

type AuthRateUser struct {
	Username  string
	Starttime time.Time
}

type RadiusService struct {
	AuthRateCache map[string]AuthRateUser
}

type AuthService struct {
	*RadiusService
}
type AcctService struct {
	*RadiusService
}
type RadsecService struct {
	AuthService *AuthService
	AcctService *AcctService
}

func (s *RadsecService) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	return []byte("radsec"), nil
}

func NewRadsecService(authService *AuthService, acctService *AcctService) *RadsecService {
	return &RadsecService{AuthService: authService, AcctService: acctService}
}

func NewAcctService(radiusService *RadiusService) *AcctService {
	return &AcctService{RadiusService: radiusService}
}

func NewAuthService(radiusService *RadiusService) *AuthService {
	return &AuthService{RadiusService: radiusService}
}

func (s *RadsecService) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	fmt.Println("Calling Server Radius:=== ", r)
	switch r.Code {
	case radius.CodeAccessRequest:
		//s.AuthService.ServeRADIUS(w, r)
		ServeRADIUS(w, r)
	case radius.CodeAccountingRequest:
		//s.AcctService.ServeRADIUS(w, r)
		ServeRADIUS(w, r)
	default:
		fmt.Println("radius radsec message", string("radius"), r.Code)
	}
}

func ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	fmt.Println("connectint to Auth/Acc server ")
}
