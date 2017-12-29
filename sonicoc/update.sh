#!/bin/bash

git clone https://github.com/openconfig/public.git

go run $GOPATH/src/github.com/openconfig/ygot/generator/generator.go -path=public,deps -output_file=sonicoc.go \
  -package_name=sonicoc -generate_fakeroot -fakeroot_name=device -compress_paths=true \
  -exclude_modules=ietf-interfaces \
  public/release/models/network-instance/openconfig-network-instance.yang \
  public/release/models/platform/openconfig-platform.yang \
  public/release/models/policy/openconfig-routing-policy.yang \
  public/release/models/lacp/openconfig-lacp.yang \
  public/release/models/system/openconfig-system.yang \
  public/release/models/lldp/openconfig-lldp.yang \
  public/release/models/interfaces/openconfig-interfaces.yang \
  public/release/models/interfaces/openconfig-if-ip.yang \
  public/release/models/interfaces/openconfig-if-aggregate.yang \
  public/release/models/interfaces/openconfig-if-ethernet.yang \
  public/release/models/interfaces/openconfig-if-ip-ext.yang
gofmt -w -s sonicoc.go
rm -rf public

