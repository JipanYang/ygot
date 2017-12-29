package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	// "github.com/golang/protobuf/proto"
	// "github.com/openconfig/ygot/ygot"

	log "github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	// oc "github.com/openconfig/ygot/sonicoc"

	gnmi "github.com/openconfig/ygot/sonic_gnmi/server"
)

var (
	port = flag.Int("port", -1, "port to listen on")
	// Certificate files.
	caCert            = flag.String("ca_crt", "", "CA certificate for client certificate validation. Optional.")
	serverCert        = flag.String("server_crt", "", "TLS server certificate")
	serverKey         = flag.String("server_key", "", "TLS server private key")
	allowNoClientCert = flag.Bool("allow_no_client_auth", false, "When set, fake_server will request but not require a client certificate.")
)

func main() {
	flag.Parse()

	/*
		// ----OpenConfig gnmi test---- //
		d, err := CreateAFTInstance()
		if err != nil {
			log.Exitf("Error creating device instance: %v", err)
		}

		j, err := ygot.EmitJSON(d, &ygot.EmitJSONConfig{
			Format: ygot.RFC7951,
			Indent: "  ",
			RFC7951Config: &ygot.RFC7951JSONConfig{
				AppendModuleName: true,
			},
		})

		// If an error was returned (which occurs if the struct's contents could not be validated
		// or an error occurred with rendering to JSON), then this should be handled by the
		// calling code.
		if err != nil {
			panic(err)
		}
		fmt.Printf("JSON: %v\n", j)

		// The generated code includes an Unmarshal function, which can be used to load
		// a data tree such as the one that we just created.
		loadd := &oc.Device{}
		if err := oc.Unmarshal([]byte(j), loadd); err != nil {
			panic(fmt.Sprintf("Can't unmarshal JSON: %v", err))
		}
		for _, e := range []bool{true} {
			g, err := renderToGNMINotifications(loadd, time.Now().Unix(), e)
			if err != nil {
				log.Exitf("Error creating notifications: %v", err)
			}

			if len(g) != 1 {
				log.Exitf("Unexpected number of notifications returned %s", len(g))
			}
			fmt.Printf("%v\n", proto.MarshalTextString(g[0]))
		}
	*/
	// ---- gnmi implementation ---- //

	switch {
	case *serverCert == "":
		log.Errorf("serverCert must be set.")
		return
	case *serverKey == "":
		log.Errorf("serverKey must be set.")
		return
	case *port < 0:
		log.Errorf("port must be >= 0.")
		return
	}

	cfg := &gnmi.Config{}

	certificate, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		log.Exitf("could not load server key pair: %s", err)
	}
	tlsCfg := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
	}
	if *allowNoClientCert {
		// RequestClientCert will ask client for a certificate but won't
		// require it to proceed. If certificate is provided, it will be
		// verified.
		tlsCfg.ClientAuth = tls.RequestClientCert
	}

	if *caCert != "" {
		ca, err := ioutil.ReadFile(*caCert)
		if err != nil {
			log.Exitf("could not read CA certificate: %s", err)
		}
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			log.Exit("failed to append CA certificate")
		}
		tlsCfg.ClientCAs = certPool
	}

	opts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}
	cfg.Port = int64(*port)
	s, err := gnmi.NewServer(cfg, opts)
	if err != nil {
		log.Errorf("Failed to create gNMI server: %v", err)
		return
	}

	log.Infof("Starting RPC server on address: %s", s.Address())
	s.Serve() // blocks until close
}

/*
// renderToGNMINotifications takes an input GoStruct and renders it to gNMI notifications. The
// timestamp is set to the ts argument. If usePathElem is set to true, the gNMI 0.4.0 path
// format is used.
func renderToGNMINotifications(s ygot.GoStruct, ts int64, usePathElem bool) ([]*gnmipb.Notification, error) {
	return ygot.TogNMINotifications(s, ts, ygot.GNMINotificationsConfig{UsePathElem: usePathElem})
}

// CreateAFTInstance creates an instance of the AFT model within a
// network instance and populates it with some example entries.
func CreateAFTInstance() (*oc.Device, error) {
	d := &oc.Device{}
	ni, err := d.NewNetworkInstance("DEFAULT")
	if err != nil {
		return nil, err
	}
	ni.Type = oc.OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE

	// Initialise the containers within the network instance model.
	ygot.BuildEmptyTree(ni)

	ip4, err := ni.Afts.NewIpv4Entry("192.0.2.1/32")
	if err != nil {
		return nil, err
	}

	nh4, err := ip4.NewNextHop(42)
	if err != nil {
		return nil, err
	}
	nh4.IpAddress = ygot.String("10.1.1.1")

	return d, nil
}
*/
